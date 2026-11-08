from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.login_throttle import enforce_login_rate_limit
from app.models.entities import AuditLog, User, UserRole
from app.schemas_auth import AuditRead, LoginRequest, TokenResponse, UserCreate, UserRead
from app.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    get_current_user,
    hash_password,
    require_roles,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


def audit(db: Session, actor_id: int | None, action: str, target: str, detail: str | None = None):
    db.add(AuditLog(
        actor_user_id=actor_id,
        action=action,
        target=target,
        detail=detail,
        created_at=datetime.now(timezone.utc),
    ))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    client_ip = request.client.host if request.client else "unknown"
    enforce_login_rate_limit(client_ip, email)

    user = db.scalar(select(User).where(User.email == email))
    stored_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    password_valid = verify_password(payload.password, stored_hash)
    if user is None or not user.is_active or not password_valid:
        # Keep the response identical for unknown, inactive and incorrect-password accounts.
        audit(db, None, "auth.login_failed", "authentication", "invalid_credentials")
        db.commit()
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.last_login_at = datetime.now(timezone.utc)
    audit(db, user.id, "auth.login", f"user:{user.id}")
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user),
        expires_in=settings.access_token_minutes * 60,
    )


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(UserRole.admin)),
):
    email = payload.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    audit(db, actor.id, "user.create", f"user:{user.id}", f"role={user.role.value}")
    db.commit()
    db.refresh(user)
    return user


@router.get("/audit", response_model=list[AuditRead])
def list_audit_events(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(UserRole.admin)),
):
    if skip < 0 or not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="skip must be >= 0 and limit 1..200")
    return db.scalars(
        select(AuditLog).order_by(AuditLog.id.desc()).offset(skip).limit(limit)
    ).all()
