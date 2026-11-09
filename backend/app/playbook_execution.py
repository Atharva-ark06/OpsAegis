"""Fail-closed state transition and recovery guidance for the playbook ledger.

This module has no dispatcher, provider client, queue consumer, or API route.
It validates state transitions and gives operators conservative next-step
guidance; it never claims that a provider action or recovery was performed.
"""

EXECUTION_TRANSITIONS = {
    "pending": frozenset({"claimed", "failed"}),
    "claimed": frozenset({"executing", "failed", "outcome_unknown"}),
    "executing": frozenset({"succeeded", "failed", "outcome_unknown"}),
    "outcome_unknown": frozenset({"succeeded", "failed"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
}

COMPENSATION_TRANSITIONS = {
    "not_requested": frozenset({"requested"}),
    "requested": frozenset({"executing", "failed"}),
    "executing": frozenset({"succeeded", "failed", "outcome_unknown"}),
    "outcome_unknown": frozenset({"succeeded", "failed"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
}


def validate_transition(current: str, requested: str, *, compensation: bool = False) -> str:
    """Return the requested state or reject an unknown/illegal transition."""
    transitions = COMPENSATION_TRANSITIONS if compensation else EXECUTION_TRANSITIONS
    allowed = transitions.get(current)
    if allowed is None:
        raise ValueError("Unknown current execution state")
    if requested not in transitions:
        raise ValueError("Unknown requested execution state")
    if requested not in allowed:
        raise ValueError("Execution state transition is not permitted")
    return requested


def recovery_guidance(execution_status: str, compensation_status: str) -> str:
    """Return a conservative, non-authorizing operator guidance code.

    The ledger is not connected to a provider dispatcher. These codes describe
    what an operator should verify next; they do not assert provider state.
    """
    if execution_status not in EXECUTION_TRANSITIONS:
        raise ValueError("Unknown execution status")
    if compensation_status not in COMPENSATION_TRANSITIONS:
        raise ValueError("Unknown compensation status")

    if compensation_status == "succeeded":
        return "verify_unisolated_state"
    if compensation_status in {"failed", "outcome_unknown"}:
        return "manual_recovery_required"
    if compensation_status in {"requested", "executing"}:
        return "operator_review_required"
    if execution_status == "outcome_unknown":
        return "reconcile_provider_state"
    if execution_status == "succeeded":
        return "separate_approval_required"
    if execution_status == "failed":
        return "verify_provider_state"
    return "not_applicable"
