import pytest

from app.playbook_execution import recovery_guidance


@pytest.mark.parametrize(
    ("execution", "compensation", "expected"),
    [
        ("pending", "not_requested", "not_applicable"),
        ("claimed", "not_requested", "not_applicable"),
        ("executing", "not_requested", "not_applicable"),
        ("succeeded", "not_requested", "separate_approval_required"),
        ("failed", "not_requested", "verify_provider_state"),
        ("outcome_unknown", "not_requested", "reconcile_provider_state"),
        ("succeeded", "requested", "operator_review_required"),
        ("succeeded", "executing", "operator_review_required"),
        ("succeeded", "succeeded", "verify_unisolated_state"),
        ("succeeded", "failed", "manual_recovery_required"),
        ("succeeded", "outcome_unknown", "manual_recovery_required"),
    ],
)
def test_recovery_guidance_is_conservative_for_each_lifecycle(execution, compensation, expected):
    assert recovery_guidance(execution, compensation) == expected


@pytest.mark.parametrize(
    ("execution", "compensation"),
    [
        ("unknown", "not_requested"),
        ("pending", "unknown"),
        ("", ""),
    ],
)
def test_recovery_guidance_rejects_unknown_states(execution, compensation):
    with pytest.raises(ValueError, match="Unknown"):
        recovery_guidance(execution, compensation)
