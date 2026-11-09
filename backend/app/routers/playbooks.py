"""Versioned, read-only playbook catalogue and dry-run previews.

This first Phase 6.3 increment deliberately has no action adapters or execution path.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import AuditLog, CorrelatedDetection, Finding, Incident, PlaybookApproval, User, UserRole
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



class ApprovalRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: int = Field(gt=0)
    lookback_minutes: int = Field(default=60, ge=5, le=1440)
    reason: str = Field(min_length=10, max_length=1000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 10:
            raise ValueError("Reason must contain at least 10 non-whitespace characters")
        return value


class ApprovalDecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=5, max_length=1000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 5:
            raise ValueError("Reason must contain at least 5 non-whitespace characters")
        return value


def _approval_response(item: PlaybookApproval):
    return {
        "id": item.id,
        "playbook_id": item.playbook_id,
        "playbook_version": item.playbook_version,
        "incident_id": item.incident_id,
        "requested_by_user_id": item.requested_by_user_id,
        "reviewed_by_user_id": item.reviewed_by_user_id,
        "input_parameters": item.input_parameters,
        "request_reason": item.request_reason,
        "decision_reason": item.decision_reason,
        "status": item.status,
        "expires_at": item.expires_at.isoformat(),
        "created_at": item.created_at.isoformat(),
        "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else None,
        "execution_enabled": False,
    }


@router.post("/{playbook_id}/approval-requests", status_code=201)
def create_approval_request(
    playbook_id: str,
    payload: ApprovalRequestInput,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
):
    definition = PLAYBOOKS.get(playbook_id)
    if definition is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if db.get(Incident, payload.incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    approval = PlaybookApproval(
        playbook_id=playbook_id,
        playbook_version=definition["version"],
        incident_id=payload.incident_id,
        requested_by_user_id=actor.id,
        input_parameters={"lookback_minutes": payload.lookback_minutes},
        request_reason=payload.reason.strip(),
        status="pending",
        expires_at=now + timedelta(hours=24),
    )
    db.add(approval)
    db.flush()
    db.add(AuditLog(
        actor_user_id=actor.id,
        action="playbook.approval_requested",
        target=f"playbook_approval:{approval.id}",
        detail=f"playbook:{playbook_id};version:{definition['version']};incident:{payload.incident_id}",
    ))
    db.commit()
    db.refresh(approval)
    return _approval_response(approval)


@router.get("/approvals")
def list_approval_requests(
    status_filter: str = "pending",
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
):
    if status_filter not in {"pending", "approved", "rejected", "expired", "all"}:
        raise HTTPException(status_code=422, detail="Invalid approval status")
    query = select(PlaybookApproval).order_by(PlaybookApproval.created_at.desc()).limit(100)
    if status_filter != "all":
        query = query.where(PlaybookApproval.status == status_filter)
    items = db.scalars(query).all()
    now = datetime.now(timezone.utc)
    results = []
    changed = False
    for item in items:
        expiry = item.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if item.status == "pending" and expiry <= now:
            item.status = "expired"
            db.add(AuditLog(
                actor_user_id=actor.id,
                action="playbook.approval_expired",
                target=f"playbook_approval:{item.id}",
                detail=f"playbook:{item.playbook_id};version:{item.playbook_version};incident:{item.incident_id}",
            ))
            changed = True
        results.append(_approval_response(item))
    if changed:
        db.commit()
    return {"items": results, "count": len(results)}


@router.post("/approvals/{approval_id}/decision")
def decide_approval_request(
    approval_id: int,
    payload: ApprovalDecisionInput,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
):
    approval = db.scalar(
        select(PlaybookApproval)
        .where(PlaybookApproval.id == approval_id)
        .with_for_update()
    )
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if approval.requested_by_user_id == actor.id:
        raise HTTPException(status_code=403, detail="A different operator must review this request")
    if approval.status != "pending":
        raise HTTPException(status_code=409, detail="Approval request is no longer pending")

    now = datetime.now(timezone.utc)
    expiry = approval.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now:
        approval.status = "expired"
        db.add(AuditLog(
            actor_user_id=actor.id,
            action="playbook.approval_expired",
            target=f"playbook_approval:{approval.id}",
            detail=f"playbook:{approval.playbook_id};version:{approval.playbook_version};incident:{approval.incident_id}",
        ))
        db.commit()
        raise HTTPException(status_code=409, detail="Approval request has expired")

    approval.status = "approved" if payload.decision == "approve" else "rejected"
    approval.reviewed_by_user_id = actor.id
    approval.reviewed_at = now
    approval.decision_reason = payload.reason.strip()
    db.add(AuditLog(
        actor_user_id=actor.id,
        action=f"playbook.approval_{approval.status}",
        target=f"playbook_approval:{approval.id}",
        detail=f"playbook:{approval.playbook_id};version:{approval.playbook_version};incident:{approval.incident_id}",
    ))
    db.commit()
    db.refresh(approval)
    return _approval_response(approval)
