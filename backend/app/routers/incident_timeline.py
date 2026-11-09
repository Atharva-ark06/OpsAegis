from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import AuditLog, CorrelatedDetection, Finding, Incident, IncidentNote, User, UserRole
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/incidents", tags=["incident investigation"])
OPERATORS = (UserRole.admin, UserRole.analyst)
_SECRET_KEYS = re.compile(r"(password|secret|token|api[_-]?key|authorization|credential|cookie)", re.I)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_KEY_VALUE = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|token|client[_-]?secret|secret|password|authorization|credential)\s*[:=]\s*[^\s,;]+")


class AnalystNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=5000)

    @field_validator("note")
    @classmethod
    def note_must_contain_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Note must contain non-whitespace text")
        return value


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): ("[REDACTED]" if _SECRET_KEYS.search(str(key)) else _redact(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value[:1000]]
    if isinstance(value, str):
        return _KEY_VALUE.sub(lambda match: match.group(1) + "=[REDACTED]", _BEARER.sub("Bearer [REDACTED]", value)[:10000])
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def _incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return incident


@router.post("/{incident_id}/notes", status_code=201)
def add_analyst_note(incident_id: int, payload: AnalystNoteCreate, db: Session = Depends(get_db),
                     actor: User = Depends(require_roles(*OPERATORS))):
    _incident_or_404(db, incident_id)
    now = datetime.now(timezone.utc)
    note = IncidentNote(incident_id=incident_id, author_user_id=actor.id,
                        note=payload.note.strip(), created_at=now)
    db.add(note)
    db.flush()
    db.add(AuditLog(actor_user_id=actor.id, action="incident.note.add",
                    target=f"incident:{incident_id}", detail=f"note_id:{note.id}"))
    db.commit()
    db.refresh(note)
    return {"id": note.id, "incident_id": note.incident_id, "author_user_id": note.author_user_id,
            "note": note.note, "created_at": note.created_at.isoformat()}


@router.get("/{incident_id}/timeline")
def get_incident_timeline(incident_id: int, db: Session = Depends(get_db),
                          actor: User = Depends(get_current_user)):
    incident = _incident_or_404(db, incident_id)
    events: list[dict[str, Any]] = [{
        "id": f"incident:{incident.id}", "type": "incident.created",
        "occurred_at": incident.created_at, "actor_user_id": None,
        "summary": "Incident created", "details": {"severity": incident.severity.value},
        "provenance": "opsaegis",
    }]
    audits = db.scalars(select(AuditLog).where(
        AuditLog.target == f"incident:{incident_id}",
        AuditLog.action.in_(("incident.update", "incident.note.add", "incident.evidence.export")),
    ).order_by(AuditLog.created_at.asc()).limit(500)).all()
    for audit in audits:
        events.append({
            "id": f"audit:{audit.id}", "type": audit.action,
            "occurred_at": audit.created_at, "actor_user_id": audit.actor_user_id,
            "summary": ("Analyst updated incident" if audit.action == "incident.update" else\n                        "Evidence export generated" if audit.action == "incident.evidence.export" else "Analyst note added"),
            "details": {"change": audit.detail or ""},
            "provenance": "audit_log",
        })
    notes = db.scalars(select(IncidentNote).where(
        IncidentNote.incident_id == incident_id
    ).order_by(IncidentNote.created_at.asc()).limit(500)).all()
    for note in notes:
        events.append({
            "id": f"note:{note.id}", "type": "incident.note",
            "occurred_at": note.created_at, "actor_user_id": note.author_user_id,
            "summary": note.note, "details": {},
            "provenance": "analyst_authored",
        })
    detections = db.scalars(select(CorrelatedDetection).where(
        CorrelatedDetection.incident_id == incident_id
    ).order_by(CorrelatedDetection.created_at.asc()).limit(200)).all()
    finding_ids = sorted({finding_id for detection in detections for finding_id in (detection.finding_ids or [])})
    findings = db.scalars(select(Finding).where(Finding.id.in_(finding_ids)).limit(500)).all() if finding_ids else []
    for detection in detections:
        events.append({
            "id": f"detection:{detection.id}", "type": "detection.correlated",
            "occurred_at": detection.created_at, "actor_user_id": None,
            "summary": detection.title,
            "details": {"rule_key": detection.rule_key, "severity": detection.severity.value,
                        "status": detection.status, "finding_ids": detection.finding_ids},
            "provenance": "correlation_engine",
        })
    for finding in findings:
        events.append({
            "id": f"finding:{finding.id}", "type": "finding.observed",
            "occurred_at": finding.first_seen_at, "actor_user_id": None,
            "summary": finding.title,
            "details": {"source_engine": finding.source_engine, "source_native_id": finding.source_native_id,
                        "severity": finding.severity.value, "status": finding.status.value,
                        "asset_id": finding.asset_id, "evidence": _redact(finding.evidence or {})},
            "provenance": "source_finding",
        })
    events.sort(key=lambda item: item["occurred_at"])
    return {
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": jsonable_encoder(events),
        "limits": {"audit_events": 500, "analyst_notes": 500, "detections": 200, "findings": 500},
    }


@router.get("/{incident_id}/evidence-export")
def export_incident_evidence(incident_id: int, db: Session = Depends(get_db),
                             actor: User = Depends(require_roles(*OPERATORS))):
    incident = _incident_or_404(db, incident_id)
    db.add(AuditLog(actor_user_id=actor.id, action="incident.evidence.export",
                    target=f"incident:{incident_id}", detail="schema_version:1.0"))
    db.commit()
    timeline = get_incident_timeline(incident_id, db, actor)
    payload = {
        "schema_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": incident.id, "title": incident.title, "severity": incident.severity.value,
            "status": incident.status, "description": incident.description,
            "resolution": incident.resolution, "created_at": incident.created_at,
            "updated_at": incident.updated_at, "closed_at": incident.closed_at,
        },
        "timeline": timeline,
        "redaction": {"applied": True, "policy": "secret-like keys and bearer/API-key patterns redacted"},
    }
    safe_payload = _redact(jsonable_encoder(payload))
    return JSONResponse(content=safe_payload, headers={
        "Content-Disposition": f'attachment; filename="opsaegis-incident-{incident_id}-evidence.json"',
        "Cache-Control": "no-store",
    })
