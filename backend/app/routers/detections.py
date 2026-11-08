from __future__ import annotations

import hashlib
import json
import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import redis as redis_lib
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import (
    AuditLog, CorrelatedDetection, DetectionNotification, DetectionSchedule, DetectionStatus,
    Finding, FindingSeverity, FindingStatus, Incident, ScheduledDetectionRun, User, UserRole,
)
from app.security import get_current_user, require_roles
from app.config import settings

router = APIRouter(prefix="/detections", tags=["detections"])
OPERATORS = (UserRole.admin, UserRole.analyst)
SEVERITY_RANK = {
    FindingSeverity.informational: 0, FindingSeverity.low: 1,
    FindingSeverity.medium: 2, FindingSeverity.high: 3,
    FindingSeverity.critical: 4, FindingSeverity.unknown: 0,
}


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


def _origin(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        port = parsed.port or 443
        if port != 443:
            return None
        return f"{parsed.hostname.lower().rstrip('.')}:{port}"
    except ValueError:
        return None


def _finding_out(item: CorrelatedDetection) -> dict:
    return {
        "id": item.id, "rule_key": item.rule_key, "fingerprint": item.fingerprint,
        "title": item.title, "description": item.description, "severity": item.severity.value,
        "finding_ids": item.finding_ids, "evidence": item.evidence,
        "incident_id": item.incident_id, "created_at": item.created_at.isoformat(),
        "last_seen_at": item.last_seen_at.isoformat(), "status": item.status,
        "acknowledged_at": item.acknowledged_at.isoformat() if item.acknowledged_at else None,
        "resolved_at": item.resolved_at.isoformat() if item.resolved_at else None,
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
    actor: User | None = Depends(require_roles(*OPERATORS)),
    evaluation_time: datetime | None = Query(default=None, include_in_schema=False),
) -> dict:
    now = evaluation_time if actor is None and evaluation_time is not None else datetime.now(timezone.utc)
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
    crowdsec_by_ip: list[tuple[str, list[Finding]]] = []
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

    for ip, wazuh_items in sorted(wazuh_by_ip.items()):
        matching_crowdsec: list[Finding] = []
        for decision_value, decision_items in crowdsec_by_ip:
            try:
                decision_network = ipaddress.ip_network(decision_value, strict=False)
                if ipaddress.ip_address(ip) in decision_network:
                    matching_crowdsec.extend(decision_items)
            except ValueError:
                if decision_value == ip:
                    matching_crowdsec.extend(decision_items)
        group = wazuh_items + matching_crowdsec
        ids = sorted({item.id for item in group})
        if not matching_crowdsec:
            continue
        candidates.append((
            "CROSS-ENGINE-001", ip, "Cross-engine IP corroboration",
            f"Wazuh telemetry and an active CrowdSec decision both reference {ip}.",
            group, {"ip": ip, "sources": sorted({item.source_engine for item in group}),
                    "finding_count": len(ids), "window_minutes": window_minutes},
        ))

    app_findings: dict[str, dict[str, list[Finding]]] = {}
    for item in findings:
        evidence = item.evidence if isinstance(item.evidence, dict) else {}
        if item.source_engine == "nuclei":
            origin = _origin(evidence.get("matched_at"))
            if origin:
                app_findings.setdefault(origin, {}).setdefault("nuclei", []).append(item)
        elif item.source_engine == "shannon":
            if evidence.get("validation_status") != "exploited":
                continue
            proof = evidence.get("proof")
            origin = _origin(evidence.get("affected_url"))
            if origin and isinstance(proof, str) and proof.strip():
                app_findings.setdefault(origin, {}).setdefault("shannon", []).append(item)

    for origin, source_groups in sorted(app_findings.items()):
        nuclei_items = source_groups.get("nuclei", [])
        shannon_items = source_groups.get("shannon", [])
        if not nuclei_items or not shannon_items:
            continue
        group = nuclei_items + shannon_items
        ids = sorted({item.id for item in group})
        candidates.append((
            "APP-VULN-CORROBORATION-001", origin,
            "Independent application assessment corroboration",
            f"Nuclei and proof-validated Shannon findings both reference HTTPS origin {origin}. This confirms target-level overlap, not an identical vulnerability.",
            group, {"origin": origin, "sources": ["nuclei", "shannon"],
                    "finding_count": len(ids), "window_minutes": window_minutes},
        ))

    created = refreshed = incidents_created = 0
    detection_ids: list[int] = []
    try:
        for rule_key, identity, title, description, group, evidence in candidates:
            ids = sorted({item.id for item in group})
            bucket = int(now.timestamp() // (window_minutes * 60))
            fingerprint = _fingerprint(rule_key, identity, bucket)
            record = db.scalar(select(CorrelatedDetection).where(
                CorrelatedDetection.fingerprint == fingerprint
            ))
            if record is not None:
                record.last_seen_at = now
                record.updated_at = now
                record.finding_ids = sorted(set(record.finding_ids).union(ids))
                record.evidence = evidence
                record.description = description
                detection_ids.append(record.id)
                refreshed += 1
                continue

            severity = max((_severity(group), FindingSeverity.high), key=lambda value: SEVERITY_RANK[value])
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
            if severity in {FindingSeverity.high, FindingSeverity.critical}:
                recipients = db.scalars(select(User).where(
                    User.is_active.is_(True), User.role.in_((UserRole.admin, UserRole.analyst))
                )).all()
                for recipient in recipients:
                    db.add(DetectionNotification(
                        user_id=recipient.id, detection_id=record.id, severity=severity,
                        title=f"{severity.value.upper()} detection: {title}"[:500],
                        message=f"{rule_key} generated detection {record.id} from finding IDs {ids}.",
                        created_at=now,
                    ))
            db.add(AuditLog(
                actor_user_id=actor.id if actor else None, action="detection.correlate",
                target=f"detection:{record.id}",
                detail=json.dumps({"rule_key": rule_key, "finding_ids": ids,
                                   "incident_id": incident.id, "severity": severity.value}),
            ))
            db.add(AuditLog(
                actor_user_id=actor.id if actor else None, action="incident.auto_create",
                target=f"incident:{incident.id}",
                detail=json.dumps({"detection_id": record.id, "rule_key": rule_key,
                                   "finding_ids": ids}),
            ))
            detection_ids.append(record.id)
            created += 1
            incidents_created += 1
        db.add(AuditLog(
            actor_user_id=actor.id if actor else None, action="detection.evaluate", target="detection-engine",
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


class ScheduleUpdate(BaseModel):
    enabled: bool
    interval_seconds: int = Field(ge=60, le=3600)
    window_minutes: int = Field(default=15, ge=1, le=1440)
    auth_threshold: int = Field(default=3, ge=3, le=20)


class DetectionStatusUpdate(BaseModel):
    status: DetectionStatus


def _schedule_dict(item: DetectionSchedule, worker_status: str = "unknown", redis_status: str = "unknown") -> dict:
    return {"enabled": item.enabled, "interval_seconds": item.interval_seconds,
            "window_minutes": item.window_minutes, "auth_threshold": item.auth_threshold,
            "updated_at": item.updated_at.isoformat(),
            "next_run_at": item.next_run_at.isoformat() if item.next_run_at else None,
            "last_scheduled_at": item.last_scheduled_at.isoformat() if item.last_scheduled_at else None,
            "worker_status": worker_status, "redis_status": redis_status}


def _run_dict(item: ScheduledDetectionRun) -> dict:
    return {"id": item.id, "status": item.status, "attempts": item.attempts,
            "window_minutes": item.window_minutes, "auth_threshold": item.auth_threshold,
            "next_attempt_at": item.next_attempt_at.isoformat(),
            "started_at": item.started_at.isoformat() if item.started_at else None,
            "finished_at": item.finished_at.isoformat() if item.finished_at else None,
            "error_code": item.error_code, "created_at": item.created_at.isoformat()}


def _notification_dict(item: DetectionNotification) -> dict:
    return {"id": item.id, "detection_id": item.detection_id, "severity": item.severity.value,
            "title": item.title, "message": item.message, "created_at": item.created_at.isoformat(),
            "read_at": item.read_at.isoformat() if item.read_at else None}


@router.get("/scheduler")
def get_scheduler(db: Session = Depends(get_db), actor: User = Depends(get_current_user)) -> dict:
    config = db.get(DetectionSchedule, 1)
    if config is None:
        config = DetectionSchedule(id=1, enabled=False, interval_seconds=300,
                                   window_minutes=15, auth_threshold=3,
                                   updated_at=datetime.now(timezone.utc))
        db.add(config)
        db.commit()
        db.refresh(config)
    worker_status, redis_status = "offline", "unavailable"
    try:
        client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True,
                                           socket_connect_timeout=0.5, socket_timeout=0.5)
        redis_status = "connected" if client.ping() else "unavailable"
        worker_status = "online" if client.get("opsaegis:detection:worker:heartbeat") else "offline"
        client.close()
    except Exception:
        pass
    return _schedule_dict(config, worker_status, redis_status)


@router.put("/scheduler")
def update_scheduler(payload: ScheduleUpdate, db: Session = Depends(get_db),
                     actor: User = Depends(require_roles(UserRole.admin))) -> dict:
    now = datetime.now(timezone.utc)
    config = db.get(DetectionSchedule, 1)
    if config is None:
        config = DetectionSchedule(id=1, updated_at=now)
        db.add(config)
    config.enabled = payload.enabled
    config.interval_seconds = payload.interval_seconds
    config.window_minutes = payload.window_minutes
    config.auth_threshold = payload.auth_threshold
    config.updated_by_user_id = actor.id
    config.updated_at = now
    config.next_run_at = now + timedelta(seconds=payload.interval_seconds) if payload.enabled else None
    db.add(AuditLog(actor_user_id=actor.id, action="detection.schedule.update",
                    target="detection-scheduler",
                    detail=json.dumps({"enabled": payload.enabled, "interval_seconds": payload.interval_seconds,
                                       "window_minutes": payload.window_minutes,
                                       "auth_threshold": payload.auth_threshold})))
    db.commit()
    db.refresh(config)
    return _schedule_dict(config)


@router.get("/runs")
def list_scheduled_runs(limit: int = Query(default=20, ge=1, le=100),
                        db: Session = Depends(get_db),
                        actor: User = Depends(get_current_user)) -> list[dict]:
    rows = db.scalars(select(ScheduledDetectionRun).order_by(
        ScheduledDetectionRun.created_at.desc(), ScheduledDetectionRun.id.desc()
    ).limit(limit)).all()
    return [_run_dict(item) for item in rows]


@router.get("/notifications")
def list_notifications(limit: int = Query(default=50, ge=1, le=100),
                       db: Session = Depends(get_db),
                       actor: User = Depends(get_current_user)) -> list[dict]:
    rows = db.scalars(select(DetectionNotification).where(
        DetectionNotification.user_id == actor.id
    ).order_by(DetectionNotification.created_at.desc(), DetectionNotification.id.desc()).limit(limit)).all()
    return [_notification_dict(item) for item in rows]


@router.patch("/notifications/{notification_id}/read")
def mark_notification_read(notification_id: int, db: Session = Depends(get_db),
                            actor: User = Depends(get_current_user)) -> dict:
    item = db.scalar(select(DetectionNotification).where(
        DetectionNotification.id == notification_id, DetectionNotification.user_id == actor.id
    ))
    if item is None:
        raise HTTPException(404, "Notification not found")
    if item.read_at is None:
        item.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(item)
    return _notification_dict(item)


@router.patch("/{detection_id}/status")
def update_detection_status(detection_id: int, payload: DetectionStatusUpdate,
                            db: Session = Depends(get_db),
                            actor: User = Depends(require_roles(*OPERATORS))) -> dict:
    item = db.get(CorrelatedDetection, detection_id)
    if item is None:
        raise HTTPException(404, "Detection not found")
    transitions = {"new": {"acknowledged"}, "acknowledged": {"investigating"},
                   "investigating": {"acknowledged", "resolved"}, "resolved": set()}
    next_status = payload.status.value
    if next_status != item.status and next_status not in transitions.get(item.status, set()):
        raise HTTPException(409, f"Invalid detection transition: {item.status} -> {next_status}")
    if next_status != item.status:
        previous = item.status
        now = datetime.now(timezone.utc)
        item.status = next_status
        item.updated_at = now
        if next_status == "acknowledged" and item.acknowledged_at is None:
            item.acknowledged_at = now
        if next_status == "resolved":
            item.resolved_at = now
        db.add(AuditLog(actor_user_id=actor.id, action="detection.status.update",
                        target=f"detection:{item.id}",
                        detail=json.dumps({"from": previous, "to": next_status})))
        db.commit()
        db.refresh(item)
    return _finding_out(item)
