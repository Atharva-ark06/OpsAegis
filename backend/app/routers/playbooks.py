"""Versioned, read-only playbook catalogue and dry-run previews.

This first Phase 6.3 increment deliberately has no action adapters or execution path.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import AuditLog, CorrelatedDetection, Finding, Incident, User, UserRole
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/playbooks", tags=["playbooks"])
OPERATORS = (UserRole.admin, UserRole.analyst)

PLAYBOOKS = {
    "incident-investigation": {
        "id": "incident-investigation",
        "name": "Incident investigation",
        "version": "1.0.0",
        "description": "Prepare a read-only investigation checklist for an existing incident.",
        "required_roles": ["admin", "analyst"],
        "inputs": {
            "incident_id": {"type": "integer", "minimum": 1, "required": True},
            "lookback_minutes": {"type": "integer", "minimum": 5, "maximum": 1440, "default": 60},
        },
        "preconditions": ["The incident exists.", "The caller is an active administrator or analyst."],
        "execution_mode": "dry_run_only",
        "external_actions_enabled": False,
    }
}


class InvestigationDryRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: int = Field(gt=0)
    lookback_minutes: int = Field(default=60, ge=5, le=1440)


@router.get("")
def list_playbooks(actor: User = Depends(get_current_user)):
    """List the static, versioned playbook definitions."""
    return {"items": list(PLAYBOOKS.values()), "count": len(PLAYBOOKS)}


@router.post("/{playbook_id}/dry-run")
def dry_run_playbook(
    playbook_id: str,
    payload: InvestigationDryRun,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
):
    """Validate preconditions and return a plan; never execute an external action."""
    definition = PLAYBOOKS.get(playbook_id)
    if definition is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if playbook_id != "incident-investigation":
        raise HTTPException(status_code=404, detail="Playbook not found")

    incident = db.get(Incident, payload.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=payload.lookback_minutes)
    detections = db.scalars(
        select(CorrelatedDetection)
        .where(
            CorrelatedDetection.incident_id == incident.id,
            CorrelatedDetection.created_at >= cutoff,
        )
        .order_by(CorrelatedDetection.created_at.asc())
        .limit(200)
    ).all()
    all_finding_ids = sorted({
        finding_id
        for detection in detections
        for finding_id in (detection.finding_ids or [])
    })
    finding_ids = all_finding_ids[:500]
    findings = db.scalars(
        select(Finding).where(Finding.id.in_(finding_ids)).limit(500)
    ).all() if finding_ids else []
    asset_ids = sorted({finding.asset_id for finding in findings if finding.asset_id is not None})

    db.add(AuditLog(
        actor_user_id=actor.id,
        action="playbook.dry_run",
        target=f"incident:{incident.id}",
        detail=f"playbook:{playbook_id};version:{definition['version']};lookback_minutes:{payload.lookback_minutes}",
    ))
    db.commit()

    return {
        "playbook_id": playbook_id,
        "playbook_version": definition["version"],
        "status": "preview_only",
        "executed": False,
        "external_actions_enabled": False,
        "generated_at": now.isoformat(),
        "inputs": payload.model_dump(),
        "preconditions": {
            "incident_exists": True,
            "operator_role": actor.role.value,
            "passed": True,
        },
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity.value,
            "status": incident.status,
        },
        "observed_context": {
            "detections_in_window": len(detections),
            "linked_findings": len(findings),
            "affected_asset_ids": asset_ids,
            "window_start": cutoff.isoformat(),
            "window_end": now.isoformat(),
            "possible_truncation": len(detections) == 200 or len(all_finding_ids) > 500 or len(findings) == 500,
        },
        "proposed_checklist": [
            "Review the incident timeline and analyst notes.",
            "Validate correlated detections against their source findings.",
            "Confirm affected assets and record analyst conclusions.",
        ],
        "side_effects": [],
        "limitations": [
            "This endpoint only prepares a preview; it does not change incident state.",
            "No external integration, command, scanner, containment, or notification action is invoked.",
        ],
    }
