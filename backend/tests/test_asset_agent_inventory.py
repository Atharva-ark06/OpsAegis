from datetime import datetime, timezone

from app.integrations.contracts import NormalizedFinding
from app.models.entities import Asset, Finding, User, UserRole
from app.security import create_access_token, hash_password
from app.routers import integrations as integrations_router


def _headers(db_session):
    user = User(email="asset-analyst@example.com", password_hash=hash_password("Strong-Test-Password-2026!"), role=UserRole.analyst, is_active=True)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return {"Authorization": f"Bearer {create_access_token(user)}"}


def test_wazuh_collection_creates_and_reuses_agent_asset(client, db_session, monkeypatch):
    headers = _headers(db_session)
    observed = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)

    class FakeAdapter:
        async def collect_findings(self, since, until=None):
            return [NormalizedFinding(source_engine="wazuh", source_native_id="agent-alert-1",
                title="Authentication alert", description=None, severity="high", observed_at=observed,
                asset_reference="web-01", evidence={"agent_id":"007","agent_name":"web-01","agent_ip":"10.0.0.7"})]

    monkeypatch.setattr(integrations_router, "WazuhIndexerAdapter", FakeAdapter)
    response = client.post("/api/v1/integrations/wazuh/collect", headers=headers)
    assert response.status_code == 200
    asset = db_session.query(Asset).filter_by(source_engine="wazuh", external_id="007").one()
    finding = db_session.query(Finding).filter_by(source_native_id="agent-alert-1").one()
    assert finding.asset_id == asset.id
    assert asset.ip_address == "10.0.0.7"
    assert asset.name == "web-01"

    client.post("/api/v1/integrations/wazuh/collect", headers=headers)
    assert db_session.query(Asset).filter_by(source_engine="wazuh", external_id="007").count() == 1
    assert db_session.query(Finding).filter_by(source_native_id="agent-alert-1").count() == 1


def test_asset_refresh_preserves_environment_and_asset_type(client, db_session, monkeypatch):
    headers = _headers(db_session)
    observed = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)

    class FakeAdapter:
        async def collect_findings(self, since):
            return [NormalizedFinding(source_engine="wazuh", source_native_id="agent-alert-2",
                title="Alert", description=None, severity="medium", observed_at=observed,
                asset_reference="web-02", evidence={"agent_id":"008","agent_name":"web-02","agent_ip":"10.0.0.8"})]

    monkeypatch.setattr(integrations_router, "WazuhIndexerAdapter", FakeAdapter)
    response = client.post("/api/v1/integrations/wazuh/collect", headers=headers)
    assert response.status_code == 200
    asset = db_session.query(Asset).filter_by(source_engine="wazuh", external_id="008").one()
    assert asset.environment == "unknown"
    assert asset.asset_type == "endpoint"
    assert asset.last_seen_at is not None
