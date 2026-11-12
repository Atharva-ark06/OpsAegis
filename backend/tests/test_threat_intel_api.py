from app.models.entities import AuditLog,ThreatIntelIOC,User,UserRole
from app.routers import threat_intel as threat_router
from app.security import create_access_token,hash_password

def auth(db_session,role):
    user=User(email=f"threat-{role.value}@example.test",password_hash=hash_password("Strong-Test-Password-2026!"),role=role,is_active=True)
    db_session.add(user);db_session.commit();db_session.refresh(user)
    return {"Authorization":f"Bearer {create_access_token(user)}"}

def test_provider_status_requires_authentication(client):
    assert client.get("/api/v1/threat-intel/providers").status_code==401

def test_viewer_can_read_but_cannot_enrich(client,db_session):
    headers=auth(db_session,UserRole.viewer)
    assert client.get("/api/v1/threat-intel/iocs",headers=headers).status_code==200
    assert client.post("/api/v1/threat-intel/enrich",headers=headers,json={"indicator_type":"ip","indicator_value":"8.8.8.8"}).status_code==403

def test_enrichment_validates_indicator_and_missing_provider_config(client,db_session,monkeypatch):
    headers=auth(db_session,UserRole.analyst)
    invalid=client.post("/api/v1/threat-intel/enrich",headers=headers,json={"indicator_type":"ip","indicator_value":"127.0.0.1"})
    assert invalid.status_code==422
    monkeypatch.setattr(threat_router.settings,"virustotal_api_key","")
    monkeypatch.setattr(threat_router.settings,"abuseipdb_api_key","")
    monkeypatch.setattr(threat_router.settings,"crowdsec_cti_api_key","")
    monkeypatch.setattr(threat_router.settings,"crowdsec_cti_api_key","")
    unavailable=client.post("/api/v1/threat-intel/enrich",headers=headers,json={"indicator_type":"ip","indicator_value":"8.8.8.8"})
    assert unavailable.status_code==503

def test_enrichment_persists_deduplicates_and_caches(client,db_session,monkeypatch):
    headers=auth(db_session,UserRole.admin)
    monkeypatch.setattr(threat_router.settings,"virustotal_api_key","test-vt")
    monkeypatch.setattr(threat_router.settings,"abuseipdb_api_key","test-abuse")
    monkeypatch.setattr(threat_router.settings,"crowdsec_cti_api_key","")
    calls={"vt":0,"abuse":0,"crowdsec":0}
    class FakeVT:
        async def enrich(self,kind,value):
            calls["vt"]+=1;return {"status":"ok","verdict":"malicious","risk_score":70,"details":{"analysis":{"malicious":7}}}
    class FakeAbuse:
        async def enrich(self,kind,value):
            calls["abuse"]+=1;return {"status":"ok","verdict":"suspicious","risk_score":30,"details":{"total_reports":4}}
    class FakeCrowdSec:
        async def enrich(self,kind,value):
            calls["crowdsec"]+=1;return {"status":"not_configured","verdict":"unknown","risk_score":None,"details":{}}
    monkeypatch.setattr(threat_router,"VirusTotalAdapter",FakeVT);monkeypatch.setattr(threat_router,"AbuseIPDBAdapter",FakeAbuse);monkeypatch.setattr(threat_router,"CrowdSecCTIAdapter",FakeCrowdSec)
    payload={"indicator_type":"ip","indicator_value":"8.8.8.8"}
    first=client.post("/api/v1/threat-intel/enrich",headers=headers,json=payload)
    second=client.post("/api/v1/threat-intel/enrich",headers=headers,json=payload)
    assert first.status_code==200 and first.json()["verdict"]=="malicious" and first.json()["risk_score"]==70
    assert first.json()["cached"] is False and second.status_code==200 and second.json()["cached"] is True
    assert calls=={"vt":1,"abuse":1,"crowdsec":1} and db_session.query(ThreatIntelIOC).count()==1
    assert db_session.query(AuditLog).filter_by(action="threat_intel.enrich").count()==1
    assert db_session.query(AuditLog).filter_by(action="threat_intel.enrich.cached").count()==1

def test_force_refresh_requeries_providers(client,db_session,monkeypatch):
    headers=auth(db_session,UserRole.analyst)
    monkeypatch.setattr(threat_router.settings,"virustotal_api_key","test-vt")
    monkeypatch.setattr(threat_router.settings,"abuseipdb_api_key","")
    class FakeVT:
        async def enrich(self,kind,value): return {"status":"ok","verdict":"clean","risk_score":0,"details":{}}
    class FakeAbuse:
        async def enrich(self,kind,value): return {"status":"not_configured","verdict":"unknown","risk_score":None,"details":{}}
    monkeypatch.setattr(threat_router,"VirusTotalAdapter",FakeVT);monkeypatch.setattr(threat_router,"AbuseIPDBAdapter",FakeAbuse)
    client.post("/api/v1/threat-intel/enrich",headers=headers,json={"indicator_type":"domain","indicator_value":"example.com"})
    refreshed=client.post("/api/v1/threat-intel/enrich",headers=headers,json={"indicator_type":"domain","indicator_value":"example.com","force_refresh":True})
    assert refreshed.status_code==200 and refreshed.json()["cached"] is False
    assert db_session.query(ThreatIntelIOC).count()==1
