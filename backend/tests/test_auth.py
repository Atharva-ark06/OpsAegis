import jwt
import pytest
from fastapi import HTTPException

from app.config import settings
from app.models.entities import AuditLog, User, UserRole
from app.security import (
    ALGORITHM,
    TOKEN_AUDIENCE,
    TOKEN_ISSUER,
    create_access_token,
    hash_password,
)


@pytest.fixture(autouse=True)
def bypass_redis_throttle_for_route_tests(monkeypatch):
    monkeypatch.setattr("app.routers.auth.enforce_login_rate_limit", lambda *_args: None)


def create_admin(db_session):
    user = User(
        email="admin@example.com",
        password_hash=hash_password("Correct-Horse-Battery-9!"),
        role=UserRole.admin,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_login_and_me(client, db_session):
    user = create_admin(db_session)
    response = client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Correct-Horse-Battery-9!"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert "password_hash" not in me.json()

    claims = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[ALGORITHM],
        issuer=TOKEN_ISSUER,
        audience=TOKEN_AUDIENCE,
    )
    assert claims["typ"] == "access"
    assert claims["jti"]


def test_invalid_login_is_rejected_and_audited(client, db_session):
    response = client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com", "password": "not-the-password"
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"
    event = db_session.query(AuditLog).filter_by(action="auth.login_failed").one()
    assert event.target == "authentication"
    assert event.detail == "invalid_credentials"
    assert "nobody@example.com" not in (event.detail or "")


def test_nonexistent_user_uses_dummy_password_verification(client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.routers.auth.verify_password",
        lambda password, encoded: calls.append((password, encoded)) or False,
    )
    response = client.post("/api/v1/auth/login", json={
        "email": "missing@example.com", "password": "not-the-password"
    })
    assert response.status_code == 401
    assert len(calls) == 1
    assert calls[0][1]


def test_rate_limiter_rejection_is_returned_by_login(client, monkeypatch):
    def reject(*_args):
        raise HTTPException(status_code=429, detail="Too many login attempts",
                            headers={"Retry-After": "60"})
    monkeypatch.setattr("app.routers.auth.enforce_login_rate_limit", reject)
    response = client.post("/api/v1/auth/login", json={
        "email": "admin@example.com", "password": "Wrong-password-123!"
    })
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"


def test_protected_asset_endpoint_requires_auth(client):
    assert client.get("/api/v1/assets").status_code == 401


def test_viewer_cannot_create_assets(client, db_session):
    user = create_admin(db_session)
    token = client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Correct-Horse-Battery-9!"
    }).json()["access_token"]
    created = client.post("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"}, json={
        "email": "viewer@example.com", "password": "Another-Strong-Password-42!", "role": "viewer"
    })
    assert created.status_code == 201
    viewer_token = client.post("/api/v1/auth/login", json={
        "email": "viewer@example.com", "password": "Another-Strong-Password-42!"
    }).json()["access_token"]
    headers = {"Authorization": f"Bearer {viewer_token}"}
    assert client.get("/api/v1/assets", headers=headers).status_code == 200
    assert client.post("/api/v1/assets", headers=headers, json={
        "name": "restricted", "asset_type": "server"
    }).status_code == 403


def test_token_role_is_loaded_from_database_not_trusted_from_claims(client, db_session):
    analyst = User(
        email="role-change@example.com",
        password_hash=hash_password("Correct-Horse-Battery-9!"),
        role=UserRole.analyst,
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()
    token = create_access_token(analyst)
    analyst.role = UserRole.viewer
    db_session.commit()
    response = client.get("/api/v1/auth/audit", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


@pytest.mark.parametrize("claims", [
    {"sub": "1", "iat": 1, "exp": 9999999999, "iss": "wrong", "aud": TOKEN_AUDIENCE,
     "typ": "access", "jti": "id"},
    {"sub": "1", "iat": 1, "exp": 9999999999, "iss": TOKEN_ISSUER, "aud": "wrong",
     "typ": "access", "jti": "id"},
    {"sub": "1", "iat": 1, "exp": 9999999999, "iss": TOKEN_ISSUER, "aud": TOKEN_AUDIENCE,
     "typ": "refresh", "jti": "id"},
    {"sub": "1", "iat": 1, "exp": 9999999999, "iss": TOKEN_ISSUER, "aud": TOKEN_AUDIENCE,
     "typ": "access"},
    {"sub": "-1", "iat": 1, "exp": 9999999999, "iss": TOKEN_ISSUER, "aud": TOKEN_AUDIENCE,
     "typ": "access", "jti": "id"},
])
def test_invalid_access_token_claims_are_rejected(client, claims):
    token = jwt.encode(claims, settings.secret_key, algorithm=ALGORITHM)
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_disabled_user_token_is_rejected(client, db_session):
    user = create_admin(db_session)
    token = create_access_token(user)
    user.is_active = False
    db_session.commit()
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_admin_can_read_audit_events(client, db_session):
    user = create_admin(db_session)
    token = client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Correct-Horse-Battery-9!"
    }).json()["access_token"]
    events = client.get("/api/v1/auth/audit", headers={"Authorization": f"Bearer {token}"})
    assert events.status_code == 200
    assert any(event["action"] == "auth.login" for event in events.json())

def test_first_admin_setup_requires_token_and_only_runs_once(client, monkeypatch):
    monkeypatch.setenv("OPS_AEGIS_BOOTSTRAP_TOKEN", "one-time-bootstrap-token-with-adequate-entropy")
    assert client.get("/api/v1/auth/setup-status").json()["setup_required"] is True
    payload = {"email": "first-admin@example.com", "password": "Strong-First-Admin-Password-42!"}
    assert client.post("/api/v1/auth/bootstrap", json=payload).status_code == 403
    created = client.post("/api/v1/auth/bootstrap", headers={"X-Setup-Token": "one-time-bootstrap-token-with-adequate-entropy"}, json=payload)
    assert created.status_code == 201
    assert created.json()["role"] == "admin"
    assert "password_hash" not in created.json()
    assert client.get("/api/v1/auth/setup-status").json()["setup_required"] is False
    again = client.post("/api/v1/auth/bootstrap", headers={"X-Setup-Token": "one-time-bootstrap-token-with-adequate-entropy"}, json={"email":"second-admin@example.com","password":"Strong-Second-Admin-Password-42!"})
    assert again.status_code == 409


def test_admin_can_list_and_update_users_but_cannot_remove_last_admin(client, db_session):
    admin = create_admin(db_session)
    token = client.post("/api/v1/auth/login", json={"email":admin.email,"password":"Correct-Horse-Battery-9!"}).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    created = client.post("/api/v1/auth/users", headers=headers, json={"email":"analyst2@example.com","password":"Another-Strong-Password-42!","role":"analyst"})
    assert created.status_code == 201
    listed = client.get("/api/v1/auth/users", headers=headers)
    assert listed.status_code == 200 and len(listed.json()) == 2
    changed = client.patch("/api/v1/auth/users/" + str(created.json()["id"]), headers=headers, json={"role":"viewer","is_active":False})
    assert changed.status_code == 200
    assert changed.json()["role"] == "viewer" and changed.json()["is_active"] is False
    last_admin = client.patch("/api/v1/auth/users/" + str(admin.id), headers=headers, json={"is_active":False})
    assert last_admin.status_code == 400
    assert client.get("/api/v1/auth/users").status_code == 401
