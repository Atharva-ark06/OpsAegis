from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from pwdlib import PasswordHash
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.entities import User, UserRole

password_hash = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hash.hash("OpsAegis-Dummy-Password-Only-2026!")
bearer = HTTPBearer(auto_error=False)
ALGORITHM = "HS256"
TOKEN_ISSUER = "opsaegis-api"
TOKEN_AUDIENCE = "opsaegis"


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    return password_hash.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hash.verify(password, encoded)
    except Exception:
        return False


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "typ": "access",
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid bearer token required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=[ALGORITHM],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": ["sub", "iat", "exp", "iss", "aud", "typ", "jti"]},
        )
        if payload.get("typ") != "access" or not isinstance(payload.get("jti"), str):
            raise jwt.InvalidTokenError("Invalid access token claims")
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject.isdecimal():
            raise jwt.InvalidTokenError("Invalid token subject")
        user_id = int(subject)
        if user_id <= 0:
            raise jwt.InvalidTokenError("Invalid token subject")
    except (jwt.PyJWTError, ValueError, TypeError):
        raise unauthorized
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_roles(*roles: UserRole):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dependency
