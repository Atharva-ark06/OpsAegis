from datetime import datetime, timezone

from app.models.entities import Incident, PlaybookApproval, PlaybookExecution, User, UserRole
from app.security import create_access_token


def _ledger_record(db_session, *, approval_id, status="pending", created_at=None, key="a" * 64):
    now = created_at or datetime.now(timezone.utc)
    item = PlaybookExecution(
        approval_id=approval_id,
        action_id="wazuh.agent_isolate",
        action_version="1.0.0",
        target_id="sensitive-agent-target",
        parameters_sha256="b" * 64,
        idempotency_key=key,
        status=status,
        compensation_status="not_requested",
        created_at=now,
        updated_at=now,
        provider_reference="provider-private-reference",
        safe_summary="internal provider detail",
    )
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)
    return item


def _approved_ledger(db_session, *, suffix=""):
    requester = User(email=f"ledger-api-requester{suffix}@example.com", password_hash="unused", role=UserRole.analyst, is_active=True)
    reviewer = User(email=f"ledger-api-reviewer{suffix}@example.com", password_hash="unused", role=UserRole.admin, is_active=True)
    incident = Incident(title="Ledger API test", status="open")
    db_session.add_all([requester, reviewer, incident])
    db_session.commit()
    approval = PlaybookApproval(
        playbook_id="incident-investigation",
        playbook_version="1.0.0",
        incident_id=incident.id,
        requested_by_user_id=requester.id,
        reviewed_by_user_id=reviewer.id,
        input_parameters={"lookback_minutes": 60},
        request_reason="Testing read-only execution ledger listing.",
        decision_reason="Approved only for read-only API test.",
        status="approved",
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        created_at=datetime.now(timezone.utc),
        reviewed_at=datetime.now(timezone.utc),
    )
    db_session.add(approval)
    db_session.commit()
    db_session.refresh(approval)
    return approval


def test_execution_ledger_read_api_returns_only_safe_status_fields(client, analyst_headers, db_session):
    approval = _approved_ledger(db_session)
    record = _ledger_record(db_session, approval_id=approval.id)

    response = client.get("/api/v1/playbooks/executions", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["execution_enabled"] is False
    item = body["items"][0]
    assert item["id"] == record.id
    assert item["approval_id"] == approval.id
    assert item["status"] == "pending"
    assert "target_id" not in item
    assert "parameters_sha256" not in item
    assert "idempotency_key" not in item
    assert "provider_reference" not in item
    assert "safe_summary" not in item


def test_execution_ledger_read_api_filters_and_bounds_results(client, analyst_headers, db_session):
    pending_approval = _approved_ledger(db_session)
    failed_approval = _approved_ledger(db_session, suffix="-second")
    _ledger_record(db_session, approval_id=pending_approval.id, status="pending", key="a" * 64)
    _ledger_record(db_session, approval_id=failed_approval.id, status="failed", key="c" * 64)

    filtered = client.get(
        f"/api/v1/playbooks/executions?status=failed&approval_id={failed_approval.id}&limit=1",
        headers=analyst_headers,
    )
    assert filtered.status_code == 200
    assert filtered.json()["count"] == 1
    assert filtered.json()["items"][0]["status"] == "failed"
    assert filtered.json()["has_more"] is False

    invalid = client.get("/api/v1/playbooks/executions?status=unknown", headers=analyst_headers)
    assert invalid.status_code == 422

    excessive = client.get("/api/v1/playbooks/executions?limit=101", headers=analyst_headers)
    assert excessive.status_code == 422


def test_execution_ledger_read_api_denies_viewers(client, db_session):
    viewer = User(
        email="ledger-api-viewer@example.com",
        password_hash="unused",
        role=UserRole.viewer,
        is_active=True,
    )
    db_session.add(viewer)
    db_session.commit()
    db_session.refresh(viewer)
    headers = {"Authorization": f"Bearer {create_access_token(viewer)}"}

    response = client.get("/api/v1/playbooks/executions", headers=headers)
    assert response.status_code == 403
