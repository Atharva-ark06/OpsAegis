from datetime import datetime, timedelta, timezone

from app.models.entities import AuditLog, CorrelatedDetection, Finding, FindingSeverity, Incident, User, UserRole
from app.security import create_access_token, hash_password


def auth_headers(db, role=UserRole.analyst):
    user = User(email=f"detection-{role.value}@example.test",
                password_hash=hash_password("Strong-Test-Password-2026!"),
                role=role, is_active=True)
    db.add(user)
    db.commit()
    return {"Authorization": f"Bearer {create_access_token(user)}"}


def add_finding(db, engine, native_id, title, evidence, minutes_ago=2, severity=FindingSeverity.high):
    observed = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    item = Finding(source_engine=engine, source_native_id=native_id, title=title,
                   description=None, severity=severity, status="new",
                   first_seen_at=observed, last_seen_at=observed, evidence=evidence)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def test_authentication_burst_creates_audited_incident_once(client, db_session):
    headers = auth_headers(db_session)
    for index in range(3):
        add_finding(db_session, "wazuh", f"auth-{index}", "Authentication failure",
                    {"groups": ["authentication"], "agent_id": "004", "agent_name": "web-01"})
    first = client.post("/api/v1/detections/evaluate?window_minutes=15&auth_threshold=3", headers=headers)
    assert first.status_code == 200
    assert first.json()["created"] == 1
    assert first.json()["incidents_created"] == 1
    assert db_session.query(Incident).count() == 1
    detection = db_session.query(CorrelatedDetection).one()
    assert len(detection.finding_ids) == 3
    second = client.post("/api/v1/detections/evaluate?window_minutes=15&auth_threshold=3", headers=headers)
    assert second.status_code == 200
    assert second.json()["created"] == 0
    assert second.json()["refreshed"] == 1
    assert db_session.query(Incident).count() == 1
    assert db_session.query(AuditLog).filter_by(action="detection.correlate").count() == 1
    add_finding(db_session, "wazuh", "auth-3", "Authentication failure",
                {"groups": ["authentication"], "agent_id": "004", "agent_name": "web-01"})
    third = client.post("/api/v1/detections/evaluate?window_minutes=15&auth_threshold=3", headers=headers)
    assert third.status_code == 200 and third.json()["created"] == 0
    assert db_session.query(Incident).count() == 1
    db_session.refresh(detection)
    assert len(detection.finding_ids) == 4


def test_cross_engine_ip_corroboration_requires_both_sources(client, db_session):
    headers = auth_headers(db_session)
    add_finding(db_session, "wazuh", "w-1", "Suspicious network activity",
                {"agent_ip": "203.0.113.10"})
    add_finding(db_session, "crowdsec", "c-1", "CrowdSec ban",
                {"scope": "Ip", "value": "203.0.113.10"})
    response = client.post("/api/v1/detections/evaluate", headers=headers)
    assert response.status_code == 200
    assert response.json()["created"] == 1
    detection = db_session.query(CorrelatedDetection).one()
    assert detection.rule_key == "CROSS-ENGINE-001"
    assert set(detection.finding_ids) == {1, 2}


def test_false_positive_findings_are_not_correlated(client, db_session):
    headers = auth_headers(db_session)
    for index in range(3):
        item = add_finding(db_session, "wazuh", f"fp-{index}", "Authentication failure",
                           {"groups": ["authentication"], "agent_id": "agent-fp"})
        item.status = "false_positive"
    db_session.commit()
    response = client.post("/api/v1/detections/evaluate", headers=headers)
    assert response.status_code == 200
    assert response.json()["created"] == 0


def test_viewers_can_read_but_cannot_run_correlation(client, db_session):
    viewer = auth_headers(db_session, UserRole.viewer)
    assert client.get("/api/v1/detections/rules", headers=viewer).status_code == 200
    assert client.get("/api/v1/detections", headers=viewer).status_code == 200
    assert client.post("/api/v1/detections/evaluate", headers=viewer).status_code == 403


def test_correlation_window_and_threshold_are_bounded(client, db_session):
    headers = auth_headers(db_session)
    assert client.post("/api/v1/detections/evaluate?window_minutes=0", headers=headers).status_code == 422
    assert client.post("/api/v1/detections/evaluate?auth_threshold=2", headers=headers).status_code == 422


def test_crowdsec_cidr_decision_matches_wazuh_agent_ip(client, db_session):
    headers = auth_headers(db_session)
    add_finding(db_session, "wazuh", "w-cidr", "Suspicious network activity",
                {"agent_ip": "203.0.113.10"})
    add_finding(db_session, "crowdsec", "c-cidr", "CrowdSec range ban",
                {"scope": "Range", "value": "203.0.113.0/24"})
    response = client.post("/api/v1/detections/evaluate", headers=headers)
    assert response.status_code == 200
    assert response.json()["created"] == 1
    assert db_session.query(CorrelatedDetection).one().rule_key == "CROSS-ENGINE-001"


def test_nuclei_and_proof_validated_shannon_correlate_by_https_origin(client, db_session):
    headers = auth_headers(db_session)
    add_finding(db_session, "nuclei", "n-1", "Exposed application endpoint",
                {"matched_at": "https://staging.example.test/admin", "template_id": "exposed-panel"})
    add_finding(db_session, "shannon", "s-1", "Confirmed authorization bypass",
                {"affected_url": "https://staging.example.test/account", "validation_status": "exploited",
                 "proof": "Verified unauthorized access response"})
    response = client.post("/api/v1/detections/evaluate", headers=headers)
    assert response.status_code == 200
    assert response.json()["created"] == 1
    detection = db_session.query(CorrelatedDetection).one()
    assert detection.rule_key == "APP-VULN-CORROBORATION-001"
    assert set(detection.finding_ids) == {1, 2}
