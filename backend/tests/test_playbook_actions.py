import asyncio

import pytest

from app.playbook_actions import (
    ACTION_CATALOG,
    ActionSpec,
    ActionRequest,
    ActionResult,
    ActionAdapterTimeout,
    execute_with_timeout,
    compensate_with_timeout,
    derive_idempotency_key,
    validate_action_contract,
    validate_idempotency_key,
    validate_action_request,
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


def test_action_catalogue_is_visible_but_never_executable(client, analyst_headers):
    response = client.get(
        "/api/v1/playbooks/incident-investigation/actions",
        headers=analyst_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["external_actions_enabled"] is False
    assert body["count"] == 1
    action = body["items"][0]
    assert action["action_id"] == "wazuh.agent_isolate"
    assert action["enabled"] is False
    assert action["adapter_registered"] is False
    assert action["execution_available"] is False
    assert action["requires_approval"] is True
    assert action["requires_independent_approver"] is True
    assert action["compensation_action_id"] == "wazuh.agent_unisolate"


def test_action_catalogue_rejects_unknown_playbook(client, analyst_headers):
    response = client.get(
        "/api/v1/playbooks/not-registered/actions",
        headers=analyst_headers,
    )
    assert response.status_code == 404



def _enabled_test_spec():
    return ActionSpec(
        action_id="test.action",
        version="1.0.0",
        description="test",
        target_type="registered_target",
        timeout_seconds=1,
        requires_approval=True,
        requires_independent_approver=True,
        idempotency_required=True,
        compensation_action_id="test.compensate",
        enabled=True,
        adapter_registered=True,
    )


class _HangingAdapter:
    async def execute(self, request):
        await asyncio.Event().wait()

    async def compensate(self, request, result):
        await asyncio.Event().wait()


class _SuccessfulAdapter:
    async def execute(self, request):
        return ActionResult("completed", "provider-123", "Action completed")

    async def compensate(self, request, result):
        return ActionResult("compensated", "provider-123", "Compensation completed")


def _valid_request(*, action_id="test.action", target_id="target-1", approval_id=1, parameters=None):
    parameters = {} if parameters is None else parameters
    return ActionRequest(
        action_id=action_id,
        target_id=target_id,
        parameters=parameters,
        idempotency_key=derive_idempotency_key(approval_id, action_id, target_id, parameters),
        approval_id=approval_id,
    )


def test_adapter_execution_timeout_is_enforced():
    request = _valid_request()
    with pytest.raises(ActionAdapterTimeout):
        asyncio.run(execute_with_timeout(_HangingAdapter(), request, _enabled_test_spec()))


def test_adapter_compensation_timeout_is_enforced():
    request = _valid_request()
    result = ActionResult("completed", "provider-123", "Action completed")
    with pytest.raises(ActionAdapterTimeout):
        asyncio.run(compensate_with_timeout(_HangingAdapter(), request, result, _enabled_test_spec()))


def test_adapter_calls_require_registered_enabled_spec_and_valid_idempotency():
    request = _valid_request()
    disabled = ActionSpec(
        action_id="test.action",
        version="1.0.0",
        description="test",
        target_type="registered_target",
        timeout_seconds=1,
        requires_approval=True,
        requires_independent_approver=True,
        idempotency_required=True,
        compensation_action_id="test.compensate",
    )
    with pytest.raises(RuntimeError, match="not registered and enabled"):
        asyncio.run(execute_with_timeout(_SuccessfulAdapter(), request, disabled))

    bad_request = ActionRequest(
        action_id="test.action",
        target_id="target-1",
        parameters={},
        idempotency_key="not-a-digest",
        approval_id=1,
    )
    with pytest.raises(ValueError, match="SHA-256"):
        asyncio.run(execute_with_timeout(_SuccessfulAdapter(), bad_request, _enabled_test_spec()))


def test_adapter_execution_and_compensation_return_distinct_results():
    request = _valid_request()
    adapter = _SuccessfulAdapter()
    result = asyncio.run(execute_with_timeout(adapter, request, _enabled_test_spec()))
    compensated = asyncio.run(compensate_with_timeout(adapter, request, result, _enabled_test_spec()))
    assert result.status == "completed"
    assert compensated.status == "compensated"
    assert result is not compensated



def test_adapter_request_must_match_the_registered_action():
    request = _valid_request(action_id="other.action")
    with pytest.raises(ValueError, match="does not match"):
        validate_action_request(request, _enabled_test_spec())


def test_adapter_request_idempotency_key_must_bind_exact_target_and_parameters():
    request = _valid_request(target_id="target-1")
    altered = ActionRequest(
        action_id=request.action_id,
        target_id="target-2",
        parameters=request.parameters,
        idempotency_key=request.idempotency_key,
        approval_id=request.approval_id,
    )
    with pytest.raises(ValueError, match="does not match"):
        validate_action_request(altered, _enabled_test_spec())


@pytest.mark.parametrize(
    "approval_id,target_id,parameters",
    [
        (0, "target-1", {}),
        (True, "target-1", {}),
        (1, "", {}),
        (1, " target-1", {}),
        (1, "x" * 257, {}),
        (1, "target-1", []),
    ],
)
def test_adapter_request_rejects_invalid_approval_target_or_parameters(approval_id, target_id, parameters):
    request = ActionRequest(
        action_id="test.action",
        target_id=target_id,
        parameters=parameters,
        idempotency_key="a" * 64,
        approval_id=approval_id,
    )
    with pytest.raises(ValueError):
        validate_action_request(request, _enabled_test_spec())


def test_idempotency_derivation_rejects_non_json_and_non_finite_values():
    with pytest.raises(ValueError, match="canonical JSON"):
        derive_idempotency_key(1, "test.action", "target-1", {"value": object()})
    with pytest.raises(ValueError, match="canonical JSON"):
        derive_idempotency_key(1, "test.action", "target-1", {"value": float("nan")})
