from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.integrations.nvd import NVDAdapter, NVDAdapterError
from app.models.entities import AuditLog, User, UserRole, Vulnerability, VulnerabilityStatus
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerability-management"])
OPS = (UserRole.admin, UserRole.analyst)

class VulnerabilityUpdate(BaseModel):
    status: VulnerabilityStatus | None = None
    remediation_notes: str | None = Field(default=None, max_length=10000)

def serialize(item: Vulnerability) -> dict:
    return {"id": item.id, "cve_id": item.cve_id, "finding_id": item.finding_id, "asset_id": item.asset_id,
        "cvss_score": item.cvss_score, "cvss_version": item.cvss_version, "cvss_severity": item.cvss_severity,
        "description": item.description, "published_at": item.published_at.isoformat() if item.published_at else None,
        "nvd_modified_at": item.nvd_modified_at.isoformat() if item.nvd_modified_at else None,
        "nvd_data_updated_at": item.nvd_data_updated_at.isoformat() if item.nvd_data_updated_at else None,
        "nvd_url": item.nvd_url, "status": item.status.value, "remediation_notes": item.remediation_notes,
        "first_seen_at": item.first_seen_at.isoformat(), "last_seen_at": item.last_seen_at.isoformat(),
        "updated_at": item.updated_at.isoformat()}

@router.get("")
def list_vulnerabilities(skip: int = Query(0, ge=0, le=100000), limit: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    status: VulnerabilityStatus | None = None, asset_id: int | None = Query(None, gt=0),
    q: str | None = Query(None, min_length=1, max_length=64),
    db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    stmt = select(Vulnerability).order_by(Vulnerability.updated_at.desc(), Vulnerability.id.desc())
    if severity: stmt = stmt.where(Vulnerability.cvss_severity == severity)
    if status: stmt = stmt.where(Vulnerability.status == status)
    if asset_id: stmt = stmt.where(Vulnerability.asset_id == asset_id)
    if q: stmt = stmt.where(Vulnerability.cve_id.ilike("%" + q.upper() + "%"))
    return [serialize(x) for x in db.scalars(stmt.offset(skip).limit(limit)).all()]

@router.get("/{vulnerability_id}")
def get_vulnerability(vulnerability_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    item = db.get(Vulnerability, vulnerability_id)
    if item is None: raise HTTPException(404, "Vulnerability not found")
    return serialize(item)

@router.post("/{vulnerability_id}/enrich")
async def enrich_vulnerability(vulnerability_id: int, force: bool = False, db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPS))):
    item = db.get(Vulnerability, vulnerability_id)
    if item is None: raise HTTPException(404, "Vulnerability not found")
    now = datetime.now(timezone.utc)
    cached = item.nvd_data_updated_at
    if cached and not force:
        cached = cached if cached.tzinfo else cached.replace(tzinfo=timezone.utc)
        if now - cached < timedelta(hours=24):
            db.add(AuditLog(actor_user_id=actor.id, action="vulnerability.nvd.cached", target=f"vulnerability:{item.id}"))
            db.commit()
            return {**serialize(item), "cached": True}
    try:
        data = await NVDAdapter().lookup(item.cve_id)
    except NVDAdapterError as exc:
        raise HTTPException(503, str(exc)) from None
    item.description = data["description"]
    item.cvss_score = data["cvss_score"]
    item.cvss_version = data["cvss_version"]
    item.cvss_severity = data["cvss_severity"]
    item.published_at = datetime.fromisoformat(data["published_at"].replace("Z", "+00:00")) if data["published_at"] else None
    item.nvd_modified_at = datetime.fromisoformat(data["modified_at"].replace("Z", "+00:00")) if data["modified_at"] else None
    item.nvd_data_updated_at = now
    item.nvd_url = data["nvd_url"]
    item.updated_at = now
    db.add(AuditLog(actor_user_id=actor.id, action="vulnerability.nvd.enrich", target=f"vulnerability:{item.id}",
        detail=json.dumps({"cve_id": item.cve_id, "cvss_version": item.cvss_version})))
    db.commit(); db.refresh(item)
    return {**serialize(item), "cached": False}

@router.patch("/{vulnerability_id}")
def update_vulnerability(vulnerability_id: int, payload: VulnerabilityUpdate, db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPS))):
    item = db.get(Vulnerability, vulnerability_id)
    if item is None: raise HTTPException(404, "Vulnerability not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes: raise HTTPException(422, "At least one field is required")
    if "status" in changes and changes["status"] is not None: item.status = changes["status"]
    if "remediation_notes" in changes: item.remediation_notes = changes["remediation_notes"]
    item.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_user_id=actor.id, action="vulnerability.update", target=f"vulnerability:{item.id}",
        detail=json.dumps({k: (v.value if isinstance(v, VulnerabilityStatus) else v) for k,v in changes.items()})))
    db.commit(); db.refresh(item)
    return serialize(item)
