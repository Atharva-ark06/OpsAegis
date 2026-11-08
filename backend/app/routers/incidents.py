from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import AuditLog, Incident, User, UserRole
from app.schemas import IncidentCreate, IncidentRead, IncidentUpdate
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/incidents", tags=["incidents"])
ALLOWED_TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"contained", "resolved", "open"},
    "contained": {"investigating", "resolved"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
}

@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db),
                    actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst))):
    now = datetime.now(timezone.utc)
    item = Incident(**payload.model_dump(), created_at=now, updated_at=now)
    db.add(item)
    db.flush()
    db.add(AuditLog(actor_user_id=actor.id, action="incident.create",
                    target=f"incident:{item.id}", detail=f"severity:{item.severity.value}"))
    db.commit()
    db.refresh(item)
    return item

@router.get("", response_model=list[IncidentRead])
def list_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                   actor: User = Depends(get_current_user)):
    if skip < 0 or not 1 <= limit <= 200:
        raise HTTPException(422, "skip must be >= 0 and limit 1..200")
    return db.scalars(select(Incident).order_by(Incident.id.desc()).offset(skip).limit(limit)).all()

@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    item = db.get(Incident, incident_id)
    if item is None:
        raise HTTPException(404, "Incident not found")
    return item

@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db),
                    actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst))):
    item = db.get(Incident, incident_id)
    if item is None:
        raise HTTPException(404, "Incident not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, "At least one incident field must be supplied")
    if "status" in changes and changes["status"] is None:
        raise HTTPException(422, "Incident status cannot be null")
    if "assigned_to_user_id" in changes and changes["assigned_to_user_id"] is not None:
        assignee = db.get(User, changes["assigned_to_user_id"])
        if assignee is None or not assignee.is_active or assignee.role not in {UserRole.admin, UserRole.analyst}:
            raise HTTPException(422, "Assignee must be an active admin or analyst")
    next_status = changes.get("status", item.status)
    if next_status != item.status and next_status not in ALLOWED_TRANSITIONS.get(item.status, set()):
        raise HTTPException(409, f"Invalid incident transition: {item.status} -> {next_status}")
    next_resolution = changes.get("resolution", item.resolution)
    if next_status in {"resolved", "closed"} and not (next_resolution and next_resolution.strip()):
        raise HTTPException(422, "A resolution note is required before resolving or closing an incident")
    previous = {"status": item.status, "assigned_to_user_id": item.assigned_to_user_id}
    for field, value in changes.items():
        setattr(item, field, value)
    now = datetime.now(timezone.utc)
    item.updated_at = now
    if next_status == "closed":
        item.closed_at = now
    elif item.status != "closed":
        item.closed_at = None
    detail_parts = []
    if "status" in changes:
        detail_parts.append(f"status:{previous['status']}->{item.status}")
    if "assigned_to_user_id" in changes:
        detail_parts.append(f"assignee:{previous['assigned_to_user_id']}->{item.assigned_to_user_id}")
    if "resolution" in changes:
        detail_parts.append("resolution:updated")
    db.add(AuditLog(actor_user_id=actor.id, action="incident.update",
                    target=f"incident:{item.id}", detail=";".join(detail_parts)))
    db.commit()
    db.refresh(item)
    return item
