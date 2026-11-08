from datetime import datetime, timezone

from app.integrations.contracts import NormalizedFinding
from app.models.entities import Finding, User, UserRole
from app.security import create_access_token, hash_password
from app.routers import integrations as integrations_router


def create_user(db_session, role):
    user = User(
        email=f"{role.value}@example.com",
        password_hash=hash_password("Strong-Test-Password-2026!"),
        role=role,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def test_wazuh_health_requires_authentication(client):
    response = client.get("/api/v1/integrations/wazuh/health")
    assert response.status_code == 401


def test_wazuh_collection_requires_analyst_or_admin(client, db_session):
    headers = create_user(db_session, UserRole.viewer)
    response = client.post("/api/v1/integrations/wazuh/collect", headers=headers)
    assert response.status_code == 403


def test_collection_persists_and_updates_without_duplicates(client, db_session, monkeypatch):
    headers = create_user(db_session, UserRole.analyst)
    observed = datetime(2026, 11, 8, 10, tzinfo=timezone.utc)

    class FakeAdapter:
        is_configured = True

        async def collect_findings(self, since):
            return [NormalizedFinding(
                source_engine="wazuh",
                source_native_id="doc-123",
                title="Repeated authentication failures",
                description="Multiple authentication failures detected",
                severity="high",
                observed_at=observed,
                asset_reference="lab-host",
                evidence={"rule_id": "5710", "agent_name": "lab-host"},
            )]

    monkeypatch.setattr(integrations_router, "WazuhIndexerAdapter", FakeAdapter)
    first = client.post("/api/v1/integrations/wazuh/collect", headers=headers)
    assert first.status_code == 200
    assert first.json()["inserted"] == 1
    assert first.json()["updated"] == 0

    second = client.post("/api/v1/integrations/wazuh/collect", headers=headers)
    assert second.status_code == 200
    assert second.json()["inserted"] == 0
    assert second.json()["updated"] == 1
    assert db_session.query(Finding).filter_by(source_engine="wazuh", source_native_id="doc-123").count() == 1


def test_collection_rejects_naive_or_too_old_since(client, db_session):
    headers = create_user(db_session, UserRole.admin)
    naive = client.post("/api/v1/integrations/wazuh/collect?since=2026-11-08T10:00:00", headers=headers)
    old = client.post("/api/v1/integrations/wazuh/collect?since=2020-01-01T00:00:00Z", headers=headers)
    assert naive.status_code == 422
    assert old.status_code == 422
