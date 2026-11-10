from datetime import datetime, timezone
import hmac
import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.login_throttle import enforce_login_rate_limit
from app.models.entities import AuditLog, User, UserRole
from app.schemas_auth import AuditRead, LoginRequest, TokenResponse, UserCreate, UserRead, UserUpdate, BootstrapRequest
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


@router.get('/setup-status')
def setup_status(db: Session = Depends(get_db)):
    return {'setup_required': db.scalar(select(User.id).limit(1)) is None, 'setup_enabled': bool(os.getenv('OPS_AEGIS_BOOTSTRAP_TOKEN'))}


@router.post('/bootstrap', response_model=UserRead, status_code=status.HTTP_201_CREATED)
def bootstrap_first_admin(payload: BootstrapRequest, request: Request, db: Session = Depends(get_db)):
    configured = os.getenv('OPS_AEGIS_BOOTSTRAP_TOKEN', '')
    supplied = request.headers.get('X-Setup-Token', '')
    if not configured or not supplied or not hmac.compare_digest(configured, supplied):
        raise HTTPException(status_code=403, detail='First-admin setup is not authorized')
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(731904221)'))
    if db.scalar(select(User.id).limit(1)) is not None:
        raise HTTPException(status_code=409, detail='Setup is already complete')
    user = User(email=payload.email.lower().strip(), password_hash=hash_password(payload.password), role=UserRole.admin, is_active=True)
    db.add(user)
    try:
        db.flush()
        audit(db, user.id, 'auth.bootstrap', f'user:{user.id}', 'first administrator provisioned')
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail='Setup could not be completed; verify no account already exists')
    db.refresh(user)
    return user


@router.get('/users', response_model=list[UserRead])
def list_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), actor: User = Depends(require_roles(UserRole.admin))):
    if skip < 0 or not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail='skip must be >= 0 and limit 1..200')
    return db.scalars(select(User).order_by(User.id).offset(skip).limit(limit)).all()


@router.patch('/users/{user_id}', response_model=UserRead)
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db), actor: User = Depends(require_roles(UserRole.admin))):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail='User not found')
    changes = payload.model_dump(exclude_unset=True)
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail='User update fields cannot be null')
    if target.id == actor.id and changes.get('is_active') is False:
        raise HTTPException(status_code=400, detail='You cannot deactivate your own account')
    removes_admin = target.role == UserRole.admin and (changes.get('role') not in (None, UserRole.admin) or changes.get('is_active') is False)
    if removes_admin:
        admins = db.scalars(select(User.id).where(User.role == UserRole.admin, User.is_active.is_(True))).all()
        if len(admins) <= 1:
            raise HTTPException(status_code=400, detail='The last active administrator cannot be demoted or deactivated')
    for key, value in changes.items():
        setattr(target, key, value)
    audit(db, actor.id, 'user.update', f'user:{target.id}', ','.join(sorted(changes)))
    db.commit()
    db.refresh(target)
    return target
