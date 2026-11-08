from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.entities import AuditLog, User, UserRole
from app.schemas_auth import LoginRequest, TokenResponse, UserCreate, UserRead
from app.security import create_access_token, hash_password, verify_password, get_current_user, require_roles

router = APIRouter(prefix="/auth", tags=["authentication"])

def audit(db: Session, actor_id: int | None, action: str, target: str, detail: str | None = None):
    db.add(AuditLog(actor_user_id=actor_id, action=action, target=target, detail=detail,
                    created_at=datetime.now(timezone.utc)))

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    user.last_login_at = datetime.now(timezone.utc)
    audit(db, user.id, "auth.login", f"user:{user.id}")
    db.commit()
    return TokenResponse(access_token=create_access_token(user), expires_in=900)

@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)):
    return user

@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                actor: User = Depends(require_roles(UserRole.admin))):
    email = payload.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(email=email, password_hash=hash_password(payload.password),
                role=payload.role, is_active=True)
    db.add(user)
    db.flush()
    audit(db, actor.id, "user.create", f"user:{user.id}", f"role={user.role.value}")
    db.commit()
    db.refresh(user)
    return user
