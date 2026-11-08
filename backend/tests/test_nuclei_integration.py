import pytest
from app.models.entities import Finding,User,UserRole
from app.security import create_access_token,hash_password
from app.routers import nuclei as nr
def headers(db,role=UserRole.admin):
 u=User(email=f"nu-{role.value}@example.com",password_hash=hash_password("Strong-Test-Password-2026!"),role=role,is_active=True);db.add(u);db.commit()
 return {"Authorization":f"Bearer {create_access_token(u)}"}
def test_target_registration_requires_admin(client,db_session):
 data={"name":"Staging app","url":"https://staging.example.test","authorization_reference":"Approved change AUTH-2026-007"}
 assert client.post("/api/v1/integrations/nuclei/targets",json=data,headers=headers(db_session,UserRole.analyst)).status_code==403
 assert client.post("/api/v1/integrations/nuclei/targets",json=data,headers=headers(db_session)).status_code==201
@pytest.mark.parametrize("url",["http://app.test","https://user:pass@app.test","https://localhost","https://127.0.0.1","https://app.test/?x=1"])
def test_rejects_unsafe_targets(client,db_session,url):
 r=client.post("/api/v1/integrations/nuclei/targets",json={"name":"Bad target","url":url,"authorization_reference":"Approved change AUTH-2026-008"},headers=headers(db_session))
 assert r.status_code==422
def test_result_dedup_preserves_triage(db_session):
 u=User(email="owner@nu.test",password_hash=hash_password("Strong-Test-Password-2026!"),role=UserRole.admin,is_active=True);db_session.add(u);db_session.commit()
 record={"template-id":"exposed-panel","matched-at":"https://app.example.test/admin","matcher-name":"status","info":{"name":"Exposed panel","severity":"high"}}
 assert nr.persist_findings(db_session,[record])==(1,0)
 f=db_session.query(Finding).filter_by(source_engine="nuclei").one();f.status="triaged";db_session.commit()
 assert nr.persist_findings(db_session,[record])==(0,1);db_session.refresh(f);assert f.status=="triaged"
def test_scan_history_role(client,db_session):
 assert client.get("/api/v1/integrations/nuclei/scans",headers=headers(db_session,UserRole.viewer)).status_code==403
