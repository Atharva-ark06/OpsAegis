"""Fail-closed state transition rules for the future playbook execution ledger.

This module has no dispatcher, provider client, queue consumer, or API route.
It only validates state transitions for a future separately reviewed executor.
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
