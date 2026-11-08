from app.models.entities import Asset,AuditLog,User,UserRole
from app.security import create_access_token,hash_password
from app.routers import integrations as router

def headers(db,role=UserRole.analyst):
    user=User(email="manager-"+role.value+"@example.test",password_hash=hash_password("Strong-Test-Password-2026!"),role=role,is_active=True)
    db.add(user);db.commit();db.refresh(user);return {"Authorization":"Bearer "+create_access_token(user)}

def test_manager_sync_creates_registered_agents_and_preserves_analyst_fields(client,db_session,monkeypatch):
    auth=headers(db_session)
    class FakeAdapter:
        is_configured=True
        async def collect_agents(self):
            return [{"id":"004","name":"api-node","ip":"10.2.0.4","status":"active","lastKeepAlive":"2026-11-08T10:00:00Z","os":{"name":"Ubuntu","version":"24.04"}},
                {"id":"000","name":"manager","ip":"127.0.0.1","status":"active"}]
    monkeypatch.setattr(router,"WazuhManagerAdapter",FakeAdapter)
    first=client.post("/api/v1/integrations/wazuh-manager/sync",headers=auth)
    assert first.status_code==200 and first.json()["created"]==1 and first.json()["skipped"]==1
    asset=db_session.query(Asset).filter_by(source_engine="wazuh",external_id="004").one()
    assert asset.agent_status=="active" and asset.os_name=="Ubuntu 24.04"
    asset.environment="production";asset.asset_type="database";db_session.commit()
    second=client.post("/api/v1/integrations/wazuh-manager/sync",headers=auth)
    assert second.status_code==200 and second.json()["unchanged"]==1
    db_session.refresh(asset)
    assert asset.environment=="production" and asset.asset_type=="database"
    assert db_session.query(AuditLog).filter_by(action="integration.wazuh_manager.sync").count()==2

def test_manager_sync_rejects_viewer(client,db_session):
    response=client.post("/api/v1/integrations/wazuh-manager/sync",headers=headers(db_session,UserRole.viewer))
    assert response.status_code==403
