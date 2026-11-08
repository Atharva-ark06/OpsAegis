import pytest
from app.models.entities import Finding, User, UserRole
from app.security import create_access_token, hash_password
from app.routers import shannon as sh

def auth_headers(db, role=UserRole.admin):
    user = User(email=f"shannon-{role.value}@example.test",
                password_hash=hash_password("Strong-Test-Password-2026!"),
                role=role, is_active=True)
    db.add(user)
    db.commit()
    return {"Authorization": f"Bearer {create_access_token(user)}"}

def target_payload():
    return {"name": "Authorized staging app", "target_url": "https://staging.example.test",
            "source_repository": "https://github.com/example-org/example-app",
            "authorization_reference": "Approved staging assessment AUTH-2026-008"}

def test_registration_is_admin_only(client, db_session):
    payload = target_payload()
    assert client.post("/api/v1/integrations/shannon/targets", json=payload,
                       headers=auth_headers(db_session, UserRole.analyst)).status_code == 403
    assert client.post("/api/v1/integrations/shannon/targets", json=payload,
                       headers=auth_headers(db_session)).status_code == 201

@pytest.mark.parametrize("url", ["http://staging.example.test", "https://127.0.0.1",
    "https://localhost", "https://metadata.google.internal", "https://staging.example.test/?token=x",
    "https://user:pass@staging.example.test", "https://staging.example.test:8443"])
def test_rejects_unsafe_target_urls(client, db_session, url):
    payload = target_payload()
    payload["target_url"] = url
    response = client.post("/api/v1/integrations/shannon/targets", json=payload, headers=auth_headers(db_session))
    assert response.status_code == 422

@pytest.mark.parametrize("repo", ["http://github.com/org/repo", "https://github.com/org/repo/tree/main",
    "https://user:pass@github.com/org/repo", "https://github.com/org/repo?token=x", "https://gitlab.com/org/repo"])
def test_requires_canonical_github_repository(client, db_session, repo):
    payload = target_payload()
    payload["source_repository"] = repo
    response = client.post("/api/v1/integrations/shannon/targets", json=payload, headers=auth_headers(db_session))
    assert response.status_code == 422

def test_execution_disabled_by_default(client, db_session, monkeypatch):
    monkeypatch.setattr(sh.settings, "shannon_enabled", False)
    payload = target_payload()
    client.post("/api/v1/integrations/shannon/targets", json=payload, headers=auth_headers(db_session))
    response = client.post("/api/v1/integrations/shannon/targets/1/scans", headers=auth_headers(db_session))
    assert response.status_code == 503

def test_finding_ingestion_requires_exploit_proof(db_session):
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        sh.persist_validated_findings(db_session, [{
            "fingerprint": "abc", "title": "Potential issue", "severity": "high",
            "affected_url": "https://staging.example.test/path",
            "validation_status": "suspected", "proof": ""}])

def test_finding_dedup_preserves_analyst_status(db_session):
    user = User(email="shannon-owner@example.test", password_hash=hash_password("Strong-Test-Password-2026!"),
                role=UserRole.admin, is_active=True)
    db_session.add(user)
    db_session.commit()
    record = {"fingerprint": "stable-shannon-finding-001", "title": "Confirmed authorization bypass",
              "severity": "high", "affected_url": "https://staging.example.test/admin",
              "validation_status": "exploited", "proof": "Reproduction evidence: unauthorized response"}
    assert sh.persist_validated_findings(db_session, [record]) == (1, 0)
    finding = db_session.query(Finding).filter_by(source_engine="shannon").one()
    finding.status = "triaged"
    db_session.commit()
    assert sh.persist_validated_findings(db_session, [record]) == (0, 1)
    db_session.refresh(finding)
    assert finding.status == "triaged"
