from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import Incident, User, UserRole
from app.schemas import IncidentCreate, IncidentRead
from app.security import get_current_user, require_roles
router = APIRouter(prefix="/incidents", tags=["incidents"])
@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db),
                    actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst))):
    item = Incident(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return item
@router.get("", response_model=list[IncidentRead])
def list_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                   actor: User = Depends(get_current_user)):
    if skip < 0 or not 1 <= limit <= 200: raise HTTPException(422, "skip must be >= 0 and limit 1..200")
    return db.scalars(select(Incident).order_by(Incident.id.desc()).offset(skip).limit(limit)).all()
@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    item = db.get(Incident, incident_id)
    if item is None: raise HTTPException(404, "Incident not found")
    return item
