from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.entities import AuditLog, User, UserRole
from app.security import require_roles

router = APIRouter(prefix="/integrations/kali", tags=["kali-terminal"])
OPERATORS = (UserRole.admin, UserRole.analyst)
COOKIE_NAME = "opsaegis_kali_session"
TOKEN_ISSUER = "opsaegis-api"
TOKEN_AUDIENCE = "opsaegis-kali-terminal"
SESSION_SECONDS = 300


def _audit(db: Session, actor: User, action: str) -> None:
    db.add(AuditLog(
        actor_user_id=actor.id,
        action=action,
        target="kali-terminal",
        detail=json.dumps({"role": actor.role.value}),
    ))
    db.commit()


def _session_token(actor: User) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": str(actor.id),
        "iat": now,
        "exp": now + timedelta(seconds=SESSION_SECONDS),
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "typ": "kali_terminal",
        "jti": str(uuid4()),
    }, settings.secret_key, algorithm="HS256")


@router.get("/health")
async def health(actor: User = Depends(require_roles(*OPERATORS))) -> dict[str, object]:
    if not settings.kali_terminal_enabled or not settings.kali_terminal_url:
        return {"integration": "kali-terminal", "configured": False,
                "status": "not_configured", "execution_enabled": False}
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
            response = await client.get(settings.kali_terminal_url.rstrip("/") + "/")
        healthy = response.status_code == 200
    except (httpx.HTTPError, ValueError):
        healthy = False
    return {"integration": "kali-terminal", "configured": True,
            "status": "healthy" if healthy else "unhealthy",
            "execution_enabled": healthy}


@router.post("/session")
def create_session(
    response: Response,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
) -> dict[str, int]:
    if not settings.kali_terminal_enabled or not settings.kali_terminal_url:
        raise HTTPException(503, "Kali terminal is not configured")
    response.set_cookie(
        key=COOKIE_NAME,
        value=_session_token(actor),
        max_age=SESSION_SECONDS,
        path="/terminal/",
        secure=settings.environment.lower() == "production",
        httponly=True,
        samesite="strict",
    )
    _audit(db, actor, "integration.kali.session.create")
    return {"expires_in": SESSION_SECONDS}


@router.post("/session/revoke")
def revoke_session(
    response: Response,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
) -> dict[str, bool]:
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/terminal/",
        secure=settings.environment.lower() == "production",
        httponly=True,
        samesite="strict",
    )
    _audit(db, actor, "integration.kali.session.revoke")
    return {"revoked": True}


@router.get("/authorize", status_code=204)
def authorize_terminal_request(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    token = request.cookies.get(COOKIE_NAME)
    unauthorized = HTTPException(401, "A valid OpsAegis terminal session is required")
    if not token:
        raise unauthorized
    try:
        claims = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": ["sub", "iat", "exp", "iss", "aud", "typ", "jti"]},
        )
        if claims.get("typ") != "kali_terminal":
            raise jwt.InvalidTokenError("Wrong token type")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.isdecimal() or int(subject) <= 0:
            raise jwt.InvalidTokenError("Invalid subject")
    except (jwt.PyJWTError, ValueError, TypeError):
        raise unauthorized
    actor = db.get(User, int(subject))
    if actor is None or not actor.is_active:
        raise unauthorized
    if actor.role not in OPERATORS:
        raise HTTPException(403, "Kali terminal access requires analyst or administrator role")
    return Response(status_code=204)
