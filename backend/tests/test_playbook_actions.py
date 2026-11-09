import pytest

from app.playbook_actions import (
    ACTION_CATALOG,
    ActionSpec,
    derive_idempotency_key,
    validate_action_contract,
    validate_idempotency_key,
)


def test_action_catalog_is_fail_closed_and_requires_compensation():
    spec = ACTION_CATALOG["wazuh.agent_isolate"]
    assert spec.enabled is False
    assert spec.adapter_registered is False
    assert spec.requires_approval is True
    assert spec.requires_independent_approver is True
    assert spec.idempotency_required is True
    assert spec.compensation_action_id == "wazuh.agent_unisolate"
    validate_action_contract(spec)


def test_idempotency_key_is_stable_and_binds_approval_target_and_parameters():
    params = {"reason": "confirmed incident", "window": 10}
    first = derive_idempotency_key(12, "wazuh.agent_isolate", "agent-007", params)
    second = derive_idempotency_key(12, "wazuh.agent_isolate", "agent-007", {"window": 10, "reason": "confirmed incident"})
    assert first == second
    assert len(first) == 64
    assert first != derive_idempotency_key(13, "wazuh.agent_isolate", "agent-007", params)
    assert first != derive_idempotency_key(12, "wazuh.agent_isolate", "agent-008", params)
    assert validate_idempotency_key(first) == first


@pytest.mark.parametrize("timeout", [0, 31, 120])
def test_action_contract_rejects_unbounded_timeout(timeout):
    spec = ActionSpec(
        action_id="test.action",
        version="1.0.0",
        description="test",
        target_type="registered_target",
        timeout_seconds=timeout,
        requires_approval=True,
        requires_independent_approver=True,
        idempotency_required=True,
        compensation_action_id="test.compensate",
    )
    with pytest.raises(ValueError, match="timeout"):
        validate_action_contract(spec)


def test_action_contract_rejects_missing_independent_approval_or_compensation():
    base = dict(
        action_id="test.action",
        version="1.0.0",
        description="test",
        target_type="registered_target",
        timeout_seconds=10,
        requires_approval=True,
        requires_independent_approver=True,
        idempotency_required=True,
        compensation_action_id="test.compensate",
    )
    with pytest.raises(ValueError, match="independent"):
        validate_action_contract(ActionSpec(**{**base, "requires_independent_approver": False}))
    with pytest.raises(ValueError, match="compensation"):
        validate_action_contract(ActionSpec(**{**base, "compensation_action_id": ""}))


def test_enabled_action_requires_registered_adapter():
    spec = ActionSpec(
        action_id="test.action",
        version="1.0.0",
        description="test",
        target_type="registered_target",
        timeout_seconds=10,
        requires_approval=True,
        requires_independent_approver=True,
        idempotency_required=True,
        compensation_action_id="test.compensate",
        enabled=True,
        adapter_registered=False,
    )
    with pytest.raises(ValueError, match="registered adapter"):
        validate_action_contract(spec)


def test_idempotency_key_rejects_arbitrary_values():
    with pytest.raises(ValueError, match="SHA-256"):
        validate_idempotency_key("user-controlled-key")
