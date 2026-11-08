from datetime import datetime, timezone
from app.models.entities import AuditLog, Finding, User, UserRole
from app.security import create_access_token, hash_password
from app.routers import integrations as integrations_router
from app.integrations.contracts import NormalizedFinding

def auth_headers(db_session, role=UserRole.analyst):
    user=User(email=f"crowdsec-{role.value}@example.com",password_hash=hash_password("Strong-Test-Password-2026!"),role=role,is_active=True)
    db_session.add(user); db_session.commit()
    return {"Authorization":f"Bearer {create_access_token(user)}"}

def test_crowdsec_health_requires_admin_or_analyst(client,db_session):
    assert client.get("/api/v1/integrations/crowdsec/health",headers=auth_headers(db_session,UserRole.viewer)).status_code==403

def test_crowdsec_collection_deduplicates_and_preserves_triage(client,db_session,monkeypatch):
    headers=auth_headers(db_session); observed=datetime(2026,11,8,10,tzinfo=timezone.utc)
    class FakeAdapter:
        is_configured=True
        async def collect_findings(self,since=None):
            return [NormalizedFinding(source_engine="crowdsec",source_native_id="decision-55",
                title="CrowdSec ban: Ip 203.0.113.8",description="ssh brute force",severity="high",
                observed_at=observed,asset_reference="203.0.113.8",evidence={"scope":"Ip","value":"203.0.113.8"})]
    monkeypatch.setattr(integrations_router,"CrowdSecLapiAdapter",FakeAdapter)
    first=client.post("/api/v1/integrations/crowdsec/collect",headers=headers)
    assert first.status_code==200 and first.json()["inserted"]==1
    finding=db_session.query(Finding).filter_by(source_engine="crowdsec",source_native_id="decision-55").one()
    finding.status="triaged"; db_session.commit()
    second=client.post("/api/v1/integrations/crowdsec/collect",headers=headers)
    assert second.status_code==200 and second.json()["updated"]==1
    db_session.refresh(finding)
    assert finding.status=="triaged"
    assert db_session.query(Finding).filter_by(source_engine="crowdsec",source_native_id="decision-55").count()==1
    assert db_session.query(AuditLog).filter_by(action="integration.crowdsec.collect").count()==2

def test_crowdsec_collection_requires_authentication(client):
    assert client.post("/api/v1/integrations/crowdsec/collect").status_code==401
