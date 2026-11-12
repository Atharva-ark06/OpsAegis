import jwt
from app.config import settings
from app.models.entities import AuditLog, User, UserRole
from app.routers.kali_terminal import COOKIE_NAME, TOKEN_AUDIENCE, TOKEN_ISSUER
from app.security import hash_password


def create_user(db_session, email, role):
    user = User(email=email, password_hash=hash_password("Strong-Test-Password-2026!"),
                role=role, is_active=True)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_kali_health_is_disabled_by_default_for_operator(client, analyst_headers, monkeypatch):
    monkeypatch.setattr(settings, "kali_terminal_enabled", False)
    response = client.get("/api/v1/integrations/kali/health", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json() == {
        "integration": "kali-terminal", "configured": False,
        "status": "not_configured", "execution_enabled": False,
    }


def test_admin_can_create_short_lived_http_only_terminal_cookie(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "kali_terminal_enabled", True)
    monkeypatch.setattr(settings, "kali_terminal_url", "http://kali-terminal.railway.internal:7681")
    admin = create_user(db_session, "kali-admin@example.com", UserRole.admin)
    from app.security import create_access_token
    response = client.post("/api/v1/integrations/kali/session",
                           headers={"Authorization": "Bearer " + create_access_token(admin)})
    assert response.status_code == 200
    assert response.json()["expires_in"] == 300
    cookie = response.headers["set-cookie"]
    assert COOKIE_NAME in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/terminal/" in cookie
    token = response.cookies.get(COOKIE_NAME)
    claims = jwt.decode(token, settings.secret_key, algorithms=["HS256"],
                        issuer=TOKEN_ISSUER, audience=TOKEN_AUDIENCE)
    assert claims["typ"] == "kali_terminal"
    assert claims["sub"] == str(admin.id)
    assert db_session.query(AuditLog).filter_by(action="integration.kali.session.create").count() == 1


def test_analyst_can_authorize_but_viewer_cannot(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "kali_terminal_enabled", True)
    monkeypatch.setattr(settings, "kali_terminal_url", "http://kali-terminal.railway.internal:7681")
    from app.security import create_access_token
    analyst = create_user(db_session, "kali-analyst@example.com", UserRole.analyst)
    token_response = client.post("/api/v1/integrations/kali/session",
        headers={"Authorization": "Bearer " + create_access_token(analyst)})
    assert token_response.status_code == 200
    session_token = token_response.cookies.get(COOKIE_NAME)
    allowed = client.get("/api/v1/integrations/kali/authorize",
                         headers={"Cookie": f"{COOKIE_NAME}={session_token}"})
    assert allowed.status_code == 204

    viewer = create_user(db_session, "kali-viewer@example.com", UserRole.viewer)
    viewer_token = client.post("/api/v1/integrations/kali/session",
        headers={"Authorization": "Bearer " + create_access_token(viewer)})
    assert viewer_token.status_code == 403


def test_terminal_authorization_rejects_missing_or_invalid_cookie(client):
    assert client.get("/api/v1/integrations/kali/authorize").status_code == 401
    assert client.get("/api/v1/integrations/kali/authorize",
                      headers={"Cookie": f"{COOKIE_NAME}=not-a-valid-token"}).status_code == 401


def test_terminal_authorization_rechecks_current_database_role(client, db_session):
    from app.security import create_access_token
    analyst = create_user(db_session, "kali-role-change@example.com", UserRole.analyst)
    token = create_access_token(analyst)
    from app.routers.kali_terminal import _session_token
    session = _session_token(analyst)
    analyst.role = UserRole.viewer
    db_session.commit()
    response = client.get("/api/v1/integrations/kali/authorize",
                          headers={"Cookie": f"{COOKIE_NAME}={session}"})
    assert response.status_code == 403


def test_terminal_session_requires_enabled_service(client, analyst_headers, monkeypatch):
    monkeypatch.setattr(settings, "kali_terminal_enabled", False)
    response = client.post("/api/v1/integrations/kali/session", headers=analyst_headers)
    assert response.status_code == 503


def test_viewer_cannot_access_terminal_health(client, db_session):
    from app.security import create_access_token
    viewer = create_user(db_session, "kali-health-viewer@example.com", UserRole.viewer)
    response = client.get("/api/v1/integrations/kali/health",
                          headers={"Authorization": "Bearer " + create_access_token(viewer)})
    assert response.status_code == 403

def test_terminal_authorization_fails_closed_when_disabled(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "kali_terminal_enabled", False)
    analyst = create_user(db_session, "kali-disabled@example.com", UserRole.analyst)
    from app.routers.kali_terminal import _session_token
    token = _session_token(analyst)
    response = client.get("/api/v1/integrations/kali/authorize",
                          headers={"Cookie": f"{COOKIE_NAME}={token}"})
    assert response.status_code == 403

