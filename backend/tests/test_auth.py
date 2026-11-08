from app.models.entities import User, UserRole
from app.security import hash_password

def create_admin(db_session):
    user = User(email="admin@example.test", password_hash=hash_password("Correct-Horse-Battery-9!"),
                role=UserRole.admin, is_active=True)
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

def test_invalid_login_is_rejected(client):
    response = client.post("/api/v1/auth/login", json={
        "email": "nobody@example.test", "password": "not-the-password"
    })
    assert response.status_code == 401

def test_protected_asset_endpoint_requires_auth(client):
    assert client.get("/api/v1/assets").status_code == 401

def test_viewer_cannot_create_assets(client, db_session):
    user = create_admin(db_session)
    token = client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Correct-Horse-Battery-9!"
    }).json()["access_token"]
    created = client.post("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"}, json={
        "email": "viewer@example.test", "password": "Another-Strong-Password-42!", "role": "viewer"
    })
    assert created.status_code == 201
    viewer_token = client.post("/api/v1/auth/login", json={
        "email": "viewer@example.test", "password": "Another-Strong-Password-42!"
    }).json()["access_token"]
    headers = {"Authorization": f"Bearer {viewer_token}"}
    assert client.get("/api/v1/assets", headers=headers).status_code == 200
    assert client.post("/api/v1/assets", headers=headers, json={
        "name": "restricted", "asset_type": "server"
    }).status_code == 403

def test_admin_can_read_audit_events(client, db_session):
    user = create_admin(db_session)
    token = client.post("/api/v1/auth/login", json={
        "email": user.email, "password": "Correct-Horse-Battery-9!"
    }).json()["access_token"]
    events = client.get("/api/v1/auth/audit", headers={"Authorization": f"Bearer {token}"})
    assert events.status_code == 200
    assert any(event["action"] == "auth.login" for event in events.json())
