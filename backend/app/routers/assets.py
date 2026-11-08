from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import Asset, User, UserRole
from app.schemas import AssetCreate, AssetRead
from app.security import get_current_user, require_roles
router = APIRouter(prefix="/assets", tags=["assets"])
@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db),
                 actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst))):
    item = Asset(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return item
@router.get("", response_model=list[AssetRead])
def list_assets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
                actor: User = Depends(get_current_user)):
    if skip < 0 or not 1 <= limit <= 200: raise HTTPException(422, "skip must be >= 0 and limit 1..200")
    return db.scalars(select(Asset).order_by(Asset.id).offset(skip).limit(limit)).all()
@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    item = db.get(Asset, asset_id)
    if item is None: raise HTTPException(404, "Asset not found")
    return item
