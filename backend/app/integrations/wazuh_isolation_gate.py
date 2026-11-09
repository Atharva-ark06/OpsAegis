"""Offline completeness gate for the future Wazuh isolation implementation.

This module performs no provider I/O and cannot authorize or execute isolation.
It only checks that a trusted operator review has supplied references for every
prerequisite recorded in the Phase 6 Wazuh isolation threat model.
"""
from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True)
class IsolationReadinessEvidence:
    """References to independently reviewed evidence; never put secrets here."""

    manager_version: str | None = None
    version_specific_api_reference: str | None = None
    written_authorization_reference: str | None = None
    isolated_staging_environment_reference: str | None = None
    disposable_agent_reference: str | None = None
    least_privilege_review_reference: str | None = None
    provider_state_verification_reference: str | None = None
    compensation_drill_reference: str | None = None
    replay_and_concurrency_test_reference: str | None = None
    audit_redaction_review_reference: str | None = None
    security_reviewer_reference: str | None = None


_REQUIRED_EVIDENCE = tuple(field.name for field in fields(IsolationReadinessEvidence))
_MAX_REFERENCE_LENGTH = 256


def missing_isolation_evidence(
    evidence: IsolationReadinessEvidence | None,
) -> tuple[str, ...]:
    """Return missing or malformed prerequisites in stable, non-secret form.

    A complete result means only that references were supplied. It does not
    validate their authenticity, prove provider behavior, or grant permission.
    """
    if type(evidence) is not IsolationReadinessEvidence:
        return _REQUIRED_EVIDENCE

    missing: list[str] = []
    for name in _REQUIRED_EVIDENCE:
        value = getattr(evidence, name)
        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
            or len(value) > _MAX_REFERENCE_LENGTH
        ):
            missing.append(name)
    return tuple(missing)


class IsolationReadinessError(RuntimeError):
    """Raised when the operator evidence register is incomplete."""


def require_isolation_readiness(
    evidence: IsolationReadinessEvidence | None,
) -> None:
    """Fail closed unless every required evidence reference is present."""
    missing = missing_isolation_evidence(evidence)
    if missing:
        names = ", ".join(missing)
        raise IsolationReadinessError(
            "Wazuh isolation implementation gate is closed; missing evidence: "
            + names
        )
