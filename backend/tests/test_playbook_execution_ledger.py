from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.entities import Incident, PlaybookApproval, PlaybookExecution, User, UserRole
from app.playbook_execution import validate_transition


def _approved_request(db_session):
    user = User(
        email="ledger-requester@example.com",
        password_hash="unused",
        role=UserRole.analyst,
        is_active=True,
    )
    reviewer = User(
        email="ledger-reviewer@example.com",
        password_hash="unused",
        role=UserRole.admin,
        is_active=True,
    )
    incident = Incident(title="Ledger test incident", status="open")
    db_session.add_all([user, reviewer, incident])
    db_session.commit()
    approval = PlaybookApproval(
        playbook_id="incident-investigation",
        playbook_version="1.0.0",
        incident_id=incident.id,
        requested_by_user_id=user.id,
        reviewed_by_user_id=reviewer.id,
        input_parameters={"lookback_minutes": 60},
        request_reason="Test durable execution ledger record.",
        decision_reason="Independently reviewed for ledger test.",
        status="approved",
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        created_at=datetime.now(timezone.utc),
        reviewed_at=datetime.now(timezone.utc),
    )
    db_session.add(approval)
    db_session.commit()
    return approval


def _execution(approval, *, key="a" * 64, action="wazuh.agent_isolate"):
    now = datetime.now(timezone.utc)
    return PlaybookExecution(
        approval_id=approval.id,
        action_id=action,
        action_version="1.0.0",
        target_id="staging-agent-001",
        parameters_sha256="b" * 64,
        idempotency_key=key,
        status="pending",
        compensation_status="not_requested",
        created_at=now,
        updated_at=now,
    )


def test_execution_ledger_persists_pending_state_without_execution(db_session):
    approval = _approved_request(db_session)
    record = _execution(approval)
    db_session.add(record)
    db_session.commit()
    db_session.refresh(record)

    assert record.status == "pending"
    assert record.compensation_status == "not_requested"
    assert record.started_at is None
    assert record.completed_at is None
    assert record.provider_reference is None


def test_execution_ledger_rejects_duplicate_idempotency_key(db_session):
    approval = _approved_request(db_session)
    db_session.add(_execution(approval))
    db_session.commit()

    second_approval = _approved_request_with_unique_users(db_session)
    db_session.add(_execution(second_approval, key="a" * 64, action="wazuh.agent_unisolate"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def _approved_request_with_unique_users(db_session):
    user = User(
        email="ledger-requester-2@example.com",
        password_hash="unused",
        role=UserRole.analyst,
        is_active=True,
    )
    reviewer = User(
        email="ledger-reviewer-2@example.com",
        password_hash="unused",
        role=UserRole.admin,
        is_active=True,
    )
    incident = Incident(title="Second ledger test incident", status="open")
    db_session.add_all([user, reviewer, incident])
    db_session.commit()
    approval = PlaybookApproval(
        playbook_id="incident-investigation",
        playbook_version="1.0.0",
        incident_id=incident.id,
        requested_by_user_id=user.id,
        reviewed_by_user_id=reviewer.id,
        input_parameters={"lookback_minutes": 60},
        request_reason="Test unique execution ledger request.",
        decision_reason="Independently reviewed for unique ledger test.",
        status="approved",
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        created_at=datetime.now(timezone.utc),
        reviewed_at=datetime.now(timezone.utc),
    )
    db_session.add(approval)
    db_session.commit()
    return approval


@pytest.mark.parametrize(
    ("current", "requested"),
    [
        ("pending", "claimed"),
        ("claimed", "executing"),
        ("executing", "succeeded"),
        ("executing", "outcome_unknown"),
        ("outcome_unknown", "succeeded"),
    ],
)
def test_valid_execution_state_transitions(current, requested):
    assert validate_transition(current, requested) == requested


@pytest.mark.parametrize(
    ("current", "requested"),
    [
        ("pending", "succeeded"),
        ("succeeded", "executing"),
        ("failed", "claimed"),
        ("executing", "claimed"),
        ("outcome_unknown", "executing"),
    ],
)
def test_invalid_execution_state_transitions_fail_closed(current, requested):
    with pytest.raises(ValueError, match="not permitted"):
        validate_transition(current, requested)


def test_compensation_has_separate_state_machine():
    assert validate_transition("not_requested", "requested", compensation=True) == "requested"
    assert validate_transition("requested", "executing", compensation=True) == "executing"
    assert validate_transition("executing", "outcome_unknown", compensation=True) == "outcome_unknown"
    with pytest.raises(ValueError, match="not permitted"):
        validate_transition("not_requested", "succeeded", compensation=True)


def test_unknown_states_are_rejected():
    with pytest.raises(ValueError, match="Unknown"):
        validate_transition("mystery", "succeeded")
    with pytest.raises(ValueError, match="Unknown"):
        validate_transition("pending", "mystery")
