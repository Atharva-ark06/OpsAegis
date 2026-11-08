from fastapi.testclient import TestClient
from app import main

def configure(monkeypatch):
    for key,value in {"token":"t"*40,"enabled":True,"egress_ack":True,"proxy":"http://proxy:3128",
      "target_hosts_csv":"staging.example.test","repositories_csv":"https://github.com/example-org/example-app","cli_version":"3.5.0"}.items():
        monkeypatch.setattr(main.settings,key,value)

async def fake_run(job_id, request):
    main.jobs[job_id]["status"]="running"

def payload(target="https://staging.example.test"):
    return {"client":"opsaegis","scan_id":1,"target_url":target,"source_repository":"https://github.com/example-org/example-app",
      "authorization_reference":"AUTH-2026-008 approved","profile":"authorized-staging"}

def test_health_fails_closed(monkeypatch):
    monkeypatch.setattr(main.settings,"enabled",False)
    response=TestClient(main.app).get("/health")
    assert response.json()["execution_enabled"] is False

def test_requires_bearer(monkeypatch):
    configure(monkeypatch)
    assert TestClient(main.app).post("/v1/scans",json=payload()).status_code==401

def test_rejects_unlisted_target(monkeypatch):
    configure(monkeypatch)
    response=TestClient(main.app).post("/v1/scans",headers={"Authorization":"Bearer "+"t"*40},json=payload("https://other.example.test"))
    assert response.status_code==403

def test_allowlisted_dispatch(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(main,"run_scan",fake_run)
    response=TestClient(main.app).post("/v1/scans",headers={"Authorization":"Bearer "+"t"*40},json=payload())
    assert response.status_code==202 and response.json()["status"]=="queued"

def test_sarif_requires_proof(tmp_path):
    report=tmp_path/"result.sarif"
    report.write_text('{"runs":[{"results":[{"ruleId":"x","message":{"text":"Possible issue"},"properties":{"affected_url":"https://staging.example.test/a"}}]}]}')
    assert main.parse_sarif(report,"https://staging.example.test")==[]
