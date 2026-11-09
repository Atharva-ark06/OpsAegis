from app.models.entities import AuditLog, Incident, User, UserRole
from app.security import create_access_token


def test_playbook_catalogue_is_authenticated_and_versioned(client, analyst_headers):
    response = client.get("/api/v1/playbooks", headers=analyst_headers)
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["id"] == "incident-investigation"
    assert item["version"] == "1.0.0"
    assert item["execution_mode"] == "dry_run_only"
    assert item["external_actions_enabled"] is False


def test_investigation_dry_run_is_preview_only_and_audited(client, analyst_headers, db_session):
    incident = Incident(title="Authentication burst", status="open")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    response = client.post(
        "/api/v1/playbooks/incident-investigation/dry-run",
        json={"incident_id": incident.id, "lookback_minutes": 120},
        headers=analyst_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "preview_only"
    assert body["executed"] is False
    assert body["external_actions_enabled"] is False
    assert body["side_effects"] == []
    assert body["incident"]["id"] == incident.id
    assert len(body["proposed_checklist"]) == 3
    event = db_session.query(AuditLog).filter_by(action="playbook.dry_run").one()
    assert event.target == f"incident:{incident.id}"
    assert "version:1.0.0" in event.detail


def test_playbook_dry_run_rejects_viewer_and_invalid_inputs(client, analyst_headers, db_session):
    viewer = User(
        email="playbook-viewer@example.com",
        password_hash="unused",
        role=UserRole.viewer,
        is_active=True,
    )
    incident = Incident(title="Viewer cannot run preview", status="open")
    db_session.add_all([viewer, incident])
    db_session.commit()
    db_session.refresh(viewer)
    db_session.refresh(incident)
    viewer_headers = {"Authorization": f"Bearer {create_access_token(viewer)}"}

    forbidden = client.post(
        "/api/v1/playbooks/incident-investigation/dry-run",
        json={"incident_id": incident.id},
        headers=viewer_headers,
    )
    assert forbidden.status_code == 403

    invalid = client.post(
        "/api/v1/playbooks/incident-investigation/dry-run",
        json={"incident_id": incident.id, "lookback_minutes": 1441},
        headers=analyst_headers,
    )
    assert invalid.status_code == 422

    unknown = client.post(
        "/api/v1/playbooks/not-registered/dry-run",
        json={"incident_id": incident.id},
        headers=analyst_headers,
    )
    assert unknown.status_code == 404
