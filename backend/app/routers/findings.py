from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import Asset, AuditLog, Finding, User, UserRole
from app.schemas import FindingCreate, FindingRead, FindingStatusUpdate
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/findings", tags=["findings"])

@router.post("", response_model=FindingRead, status_code=status.HTTP_201_CREATED)
def create_finding(payload: FindingCreate, db: Session = Depends(get_db),
                   actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst))):
    data = payload.model_dump()
    if data["asset_id"] is not None and db.get(Asset, data["asset_id"]) is None:
        raise HTTPException(404, "Asset not found")
    now = datetime.now(timezone.utc)
    item = Finding(**data, first_seen_at=now, last_seen_at=now)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

@router.get("", response_model=list[FindingRead])
def list_findings(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                  actor: User = Depends(get_current_user)):
    if skip < 0 or not 1 <= limit <= 200:
        raise HTTPException(422, "skip must be >= 0 and limit 1..200")
    return db.scalars(select(Finding).order_by(Finding.id.desc()).offset(skip).limit(limit)).all()

@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    item = db.get(Finding, finding_id)
    if item is None:
        raise HTTPException(404, "Finding not found")
    return item

@router.patch("/{finding_id}/status", response_model=FindingRead)
def update_finding_status(finding_id: int, payload: FindingStatusUpdate,
                          db: Session = Depends(get_db),
                          actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst))):
    item = db.get(Finding, finding_id)
    if item is None:
        raise HTTPException(404, "Finding not found")
    previous = item.status.value
    if payload.status == item.status:
        return item
    item.status = payload.status
    db.add(AuditLog(actor_user_id=actor.id, action="finding.status.update",
                    target=f"finding:{item.id}",
                    detail=f"status:{previous}->{payload.status.value}"))
    db.commit()
    db.refresh(item)
    return item
