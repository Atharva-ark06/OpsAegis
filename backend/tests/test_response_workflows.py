from app.models.entities import AuditLog, User, UserRole
from app.security import create_access_token

def test_finding_triage_is_role_gated_and_audited(client, analyst_headers, db_session):
    created = client.post("/api/v1/findings", json={
        "source_engine": "unit-test", "title": "Triage me", "severity": "medium"
    }, headers=analyst_headers)
    finding_id = created.json()["id"]
    response = client.patch(f"/api/v1/findings/{finding_id}/status",
                            json={"status": "triaged"}, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "triaged"
    event = db_session.query(AuditLog).filter_by(action="finding.status.update").one()
    assert event.target == f"finding:{finding_id}"
    assert "new->triaged" in event.detail

def test_viewer_cannot_change_finding_status(client, analyst_headers, db_session):
    created = client.post("/api/v1/findings", json={
        "source_engine": "unit-test", "title": "Viewer test"
    }, headers=analyst_headers)
    viewer = User(email="viewer@example.com", password_hash="unused",
                  role=UserRole.viewer, is_active=True)
    db_session.add(viewer)
    db_session.commit()
    db_session.refresh(viewer)
    headers = {"Authorization": f"Bearer {create_access_token(viewer)}"}
    response = client.patch(f"/api/v1/findings/{created.json()['id']}/status",
                            json={"status": "triaged"}, headers=headers)
    assert response.status_code == 403

def test_incident_lifecycle_assignment_and_resolution(client, analyst_headers, db_session):
    analyst = db_session.query(User).filter_by(email="analyst@example.com").one()
    created = client.post("/api/v1/incidents", json={
        "title": "Suspicious authentication activity", "severity": "high"
    }, headers=analyst_headers)
    incident_id = created.json()["id"]
    assigned = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "assigned_to_user_id": analyst.id, "status": "investigating"
    }, headers=analyst_headers)
    assert assigned.status_code == 200
    assert assigned.json()["assigned_to_user_id"] == analyst.id
    blocked = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "resolved"
    }, headers=analyst_headers)
    assert blocked.status_code == 422
    resolved = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "resolved", "resolution": "Credential reset and sessions revoked."
    }, headers=analyst_headers)
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    closed = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "closed"
    }, headers=analyst_headers)
    assert closed.status_code == 200
    assert closed.json()["closed_at"] is not None
    events = db_session.query(AuditLog).filter_by(target=f"incident:{incident_id}").all()
    assert len(events) >= 3

def test_incident_rejects_invalid_transition_and_viewer_assignee(client, analyst_headers, db_session):
    created = client.post("/api/v1/incidents", json={"title": "Invalid transition"},
                          headers=analyst_headers)
    incident_id = created.json()["id"]
    invalid = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "contained"
    }, headers=analyst_headers)
    assert invalid.status_code == 409
    viewer = User(email="readonly@example.com", password_hash="unused",
                  role=UserRole.viewer, is_active=True)
    db_session.add(viewer)
    db_session.commit()
    invalid_assignee = client.patch(f"/api/v1/incidents/{incident_id}", json={
        "assigned_to_user_id": viewer.id
    }, headers=analyst_headers)
    assert invalid_assignee.status_code == 422

def test_incident_create_status_cannot_be_forged(client, analyst_headers):
    response = client.post("/api/v1/incidents", json={
        "title": "Cannot create already resolved", "status": "resolved"
    }, headers=analyst_headers)
    assert response.status_code == 201
    assert response.json()["status"] == "open"
