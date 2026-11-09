from datetime import datetime, timedelta, timezone

from app.models.entities import AuditLog, Incident, PlaybookApproval, User, UserRole
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



def _create_second_operator(db_session, email="reviewer@example.com"):
    reviewer = User(
        email=email,
        password_hash="unused",
        role=UserRole.analyst,
        is_active=True,
    )
    db_session.add(reviewer)
    db_session.commit()
    db_session.refresh(reviewer)
    return reviewer


def test_approval_requires_a_different_operator_and_records_decision(client, analyst_headers, db_session):
    requester = db_session.query(User).filter_by(email="analyst@example.com").one()
    incident = Incident(title="Approval workflow test", status="open")
    reviewer = _create_second_operator(db_session)
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    requested = client.post(
        "/api/v1/playbooks/incident-investigation/approval-requests",
        json={
            "incident_id": incident.id,
            "lookback_minutes": 60,
            "reason": "Request a second analyst review of this investigation plan.",
        },
        headers=analyst_headers,
    )
    assert requested.status_code == 201
    approval = requested.json()
    assert approval["status"] == "pending"
    assert approval["execution_enabled"] is False
    assert approval["requested_by_user_id"] == requester.id

    requester_cannot_approve = client.post(
        f"/api/v1/playbooks/approvals/{approval['id']}/decision",
        json={"decision": "approve", "reason": "Reviewed and accepted."},
        headers=analyst_headers,
    )
    assert requester_cannot_approve.status_code == 403

    reviewer_headers = {"Authorization": f"Bearer {create_access_token(reviewer)}"}
    decided = client.post(
        f"/api/v1/playbooks/approvals/{approval['id']}/decision",
        json={"decision": "approve", "reason": "Reviewed the plan and approve the preview."},
        headers=reviewer_headers,
    )
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    assert decided.json()["reviewed_by_user_id"] == reviewer.id
    assert decided.json()["execution_enabled"] is False

    event = db_session.query(AuditLog).filter_by(action="playbook.approval_approved").one()
    assert event.target == f"playbook_approval:{approval['id']}"


def test_approval_rejection_and_duplicate_decision_are_enforced(client, analyst_headers, db_session):
    incident = Incident(title="Reject workflow test", status="open")
    reviewer = _create_second_operator(db_session, "rejector@example.com")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    requested = client.post(
        "/api/v1/playbooks/incident-investigation/approval-requests",
        json={"incident_id": incident.id, "reason": "Please independently review this investigation proposal."},
        headers=analyst_headers,
    )
    approval_id = requested.json()["id"]
    reviewer_headers = {"Authorization": f"Bearer {create_access_token(reviewer)}"}

    rejected = client.post(
        f"/api/v1/playbooks/approvals/{approval_id}/decision",
        json={"decision": "reject", "reason": "The submitted plan needs further evidence."},
        headers=reviewer_headers,
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    duplicate = client.post(
        f"/api/v1/playbooks/approvals/{approval_id}/decision",
        json={"decision": "approve", "reason": "Attempt a second decision."},
        headers=reviewer_headers,
    )
    assert duplicate.status_code == 409


def test_approval_request_rejects_viewer_and_expires(client, analyst_headers, db_session):
    incident = Incident(title="Expired approval test", status="open")
    viewer = User(
        email="approval-viewer@example.com",
        password_hash="unused",
        role=UserRole.viewer,
        is_active=True,
    )
    db_session.add_all([incident, viewer])
    db_session.commit()
    db_session.refresh(incident)
    db_session.refresh(viewer)
    viewer_headers = {"Authorization": f"Bearer {create_access_token(viewer)}"}

    forbidden = client.post(
        "/api/v1/playbooks/incident-investigation/approval-requests",
        json={"incident_id": incident.id, "reason": "This viewer cannot request an approval."},
        headers=viewer_headers,
    )
    assert forbidden.status_code == 403

    requested = client.post(
        "/api/v1/playbooks/incident-investigation/approval-requests",
        json={"incident_id": incident.id, "reason": "Request a review that will expire after one day."},
        headers=analyst_headers,
    )
    approval_id = requested.json()["id"]
    approval = db_session.get(PlaybookApproval, approval_id)
    approval.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    reviewer = _create_second_operator(db_session, "expiry-reviewer@example.com")
    reviewer_headers = {"Authorization": f"Bearer {create_access_token(reviewer)}"}
    expired = client.post(
        f"/api/v1/playbooks/approvals/{approval_id}/decision",
        json={"decision": "approve", "reason": "Trying to approve an expired request."},
        headers=reviewer_headers,
    )
    assert expired.status_code == 409
    db_session.refresh(approval)
    assert approval.status == "expired"
