from __future__ import annotations

import hashlib
import json
import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import (
    AuditLog, CorrelatedDetection, Finding, FindingSeverity, FindingStatus,
    Incident, User, UserRole,
)
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/detections", tags=["detections"])
OPERATORS = (UserRole.admin, UserRole.analyst)
SEVERITY_RANK = {
    FindingSeverity.informational: 0, FindingSeverity.low: 1,
    FindingSeverity.medium: 2, FindingSeverity.high: 3,
    FindingSeverity.critical: 4, FindingSeverity.unknown: 0,
}


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _severity(items: list[Finding]) -> FindingSeverity:
    return max((item.severity for item in items), key=lambda value: SEVERITY_RANK[value], default=FindingSeverity.medium)


def _fingerprint(rule_key: str, identity: str, window_bucket: int) -> str:
    material = rule_key + "|" + identity + "|" + str(window_bucket)
    return hashlib.sha256(material.encode()).hexdigest()


def _is_authentication_finding(item: Finding) -> bool:
    evidence = item.evidence if isinstance(item.evidence, dict) else {}
    groups = evidence.get("groups", [])
    group_values = {str(value).lower() for value in groups} if isinstance(groups, list) else set()
    text = (item.title + " " + (item.description or "")).lower()
    return "authentication" in group_values or any(
        phrase in text for phrase in (
            "authentication failure", "authentication failures", "failed login",
            "login failure", "invalid password", "ssh brute force",
        )
    )


def _agent_identity(item: Finding) -> str | None:
    evidence = item.evidence if isinstance(item.evidence, dict) else {}
    value = evidence.get("agent_id") or evidence.get("agent_name")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()[:255]
    return None


def _finding_out(item: CorrelatedDetection) -> dict:
    return {
        "id": item.id, "rule_key": item.rule_key, "fingerprint": item.fingerprint,
        "title": item.title, "description": item.description, "severity": item.severity.value,
        "finding_ids": item.finding_ids, "evidence": item.evidence,
        "incident_id": item.incident_id, "created_at": item.created_at.isoformat(),
        "last_seen_at": item.last_seen_at.isoformat(),
    }


@router.get("/rules")
def list_rules(actor: User = Depends(get_current_user)) -> list[dict]:
    return [
        {"key": "AUTH-BRUTE-001", "name": "Repeated authentication failures",
         "description": "Three or more Wazuh authentication-related findings for the same identified agent within the selected window.",
         "sources": ["wazuh"], "default_threshold": 3, "default_window_minutes": 15,
         "severity": "high", "enabled": True},
        {"key": "CROSS-ENGINE-001", "name": "Cross-engine IP corroboration",
         "description": "A Wazuh alert identifying an agent IP matches an active CrowdSec IP/range decision.",
         "sources": ["wazuh", "crowdsec"], "default_threshold": 2, "default_window_minutes": 60,
         "severity": "high", "enabled": True},
    ]


@router.get("")
def list_detections(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                    actor: User = Depends(get_current_user)) -> list[dict]:
    if skip < 0 or not 1 <= limit <= 200:
        raise HTTPException(422, "skip must be >= 0 and limit 1..200")
    records = db.scalars(select(CorrelatedDetection).order_by(
        CorrelatedDetection.last_seen_at.desc(), CorrelatedDetection.id.desc()
    ).offset(skip).limit(limit)).all()
    return [_finding_out(item) for item in records]


@router.post("/evaluate")
def evaluate_detections(
    window_minutes: int = Query(default=15, ge=1, le=1440),
    auth_threshold: int = Query(default=3, ge=3, le=20),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
) -> dict:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)
    findings = db.scalars(select(Finding).where(
        Finding.last_seen_at >= cutoff,
        Finding.status != FindingStatus.false_positive,
    ).order_by(Finding.last_seen_at.asc()).limit(5000)).all()

    candidates: list[tuple[str, str, str, str, list[Finding], dict]] = []

    auth_groups: dict[str, list[Finding]] = {}
    for item in findings:
        if item.source_engine != "wazuh" or not _is_authentication_finding(item):
            continue
        identity = _agent_identity(item)
        if identity:
            auth_groups.setdefault(identity, []).append(item)

    for identity, items in auth_groups.items():
        unique = {item.id: item for item in items}
        group = list(unique.values())
        if len(group) < auth_threshold:
            continue
        ids = sorted(unique)
        candidates.append((
            "AUTH-BRUTE-001", identity, "Repeated authentication failures",
            f"{len(group)} authentication-related Wazuh findings for agent {identity} within {window_minutes} minutes.",
            group, {"agent_identity": identity, "count": len(group), "window_minutes": window_minutes},
        ))

    wazuh_by_ip: dict[str, list[Finding]] = {}
    crowdsec_by_ip: dict[str, list[Finding]] = {}
    for item in findings:
        evidence = item.evidence if isinstance(item.evidence, dict) else {}
        if item.source_engine == "wazuh":
            ip = evidence.get("agent_ip")
            if isinstance(ip, str) and ip.strip():
                wazuh_by_ip.setdefault(ip.strip().lower(), []).append(item)
        elif item.source_engine == "crowdsec":
            scope = str(evidence.get("scope") or "").lower()
            value = evidence.get("value")
            if scope in {"ip", "range"} and isinstance(value, str) and value.strip():
                crowdsec_by_ip.append((value.strip().lower(), [item]))

    for ip in sorted(set(wazuh_by_ip).intersection(crowdsec_by_ip)):
        group = wazuh_by_ip[ip] + crowdsec_by_ip[ip]
        ids = sorted({item.id for item in group})
        if len({item.source_engine for item in group}) < 2:
            continue
        candidates.append((
            "CROSS-ENGINE-001", ip, "Cross-engine IP corroboration",
            f"Wazuh telemetry and an active CrowdSec decision both reference {ip}.",
            group, {"ip": ip, "sources": sorted({item.source_engine for item in group}),
                    "finding_count": len(ids), "window_minutes": window_minutes},
        ))

    created = refreshed = incidents_created = 0
    detection_ids: list[int] = []
    try:
        for rule_key, identity, title, description, group, evidence in candidates:
            ids = sorted({item.id for item in group})
            bucket = int(now.timestamp() // (window_minutes * 60))\n            fingerprint = _fingerprint(rule_key, identity, bucket)
            record = db.scalar(select(CorrelatedDetection).where(
                CorrelatedDetection.fingerprint == fingerprint
            ))
            if record is not None:
                record.last_seen_at = now
                detection_ids.append(record.id)
                refreshed += 1
                continue

            severity = _severity(group)
            incident = Incident(
                title=f"[{rule_key}] {title}"[:500], severity=severity, status="open",
                description=(description + " Source finding IDs: " + ", ".join(map(str, ids)))[:10000],
                created_at=now, updated_at=now,
            )
            db.add(incident)
            db.flush()
            record = CorrelatedDetection(
                rule_key=rule_key, fingerprint=fingerprint, title=title,
                description=description, severity=severity, finding_ids=ids,
                evidence=evidence, incident_id=incident.id, created_at=now, last_seen_at=now,
            )
            db.add(record)
            db.flush()
            db.add(AuditLog(
                actor_user_id=actor.id, action="detection.correlate",
                target=f"detection:{record.id}",
                detail=json.dumps({"rule_key": rule_key, "finding_ids": ids,
                                   "incident_id": incident.id, "severity": severity.value}),
            ))
            db.add(AuditLog(
                actor_user_id=actor.id, action="incident.auto_create",
                target=f"incident:{incident.id}",
                detail=json.dumps({"detection_id": record.id, "rule_key": rule_key,
                                   "finding_ids": ids}),
            ))
            detection_ids.append(record.id)
            created += 1
            incidents_created += 1
        db.add(AuditLog(
            actor_user_id=actor.id, action="detection.evaluate", target="detection-engine",
            detail=json.dumps({"window_minutes": window_minutes, "auth_threshold": auth_threshold,
                               "candidates": len(candidates), "created": created,
                               "refreshed": refreshed}),
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {"window_minutes": window_minutes, "auth_threshold": auth_threshold,
            "findings_considered": len(findings), "candidates": len(candidates),
            "created": created, "refreshed": refreshed,
            "incidents_created": incidents_created, "detection_ids": detection_ids}
