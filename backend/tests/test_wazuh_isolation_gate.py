import pytest

from app.integrations.wazuh_isolation_gate import (
    IsolationReadinessError,
    IsolationReadinessEvidence,
    missing_isolation_evidence,
    require_isolation_readiness,
)


def complete_evidence():
    return IsolationReadinessEvidence(
        manager_version="operator-record:wazuh-version",
        version_specific_api_reference="review:api-reference",
        written_authorization_reference="approval:written-scope",
        isolated_staging_environment_reference="environment:isolated-staging",
        disposable_agent_reference="asset:disposable-agent",
        least_privilege_review_reference="review:service-identity",
        provider_state_verification_reference="test:provider-state-query",
        compensation_drill_reference="test:approved-compensation-drill",
        replay_and_concurrency_test_reference="test:replay-concurrency",
        audit_redaction_review_reference="review:audit-redaction",
        security_reviewer_reference="review:independent-security-reviewer",
    )


def test_missing_evidence_closes_gate_by_default():
    missing = missing_isolation_evidence(None)
    assert "manager_version" in missing
    assert "written_authorization_reference" in missing
    assert len(missing) == 11
    with pytest.raises(IsolationReadinessError, match="gate is closed"):
        require_isolation_readiness(None)


def test_complete_reference_register_passes_completeness_check_only():
    require_isolation_readiness(complete_evidence())
    assert missing_isolation_evidence(complete_evidence()) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("manager_version", ""),
        ("written_authorization_reference", "   "),
        ("least_privilege_review_reference", " leading-space"),
        ("provider_state_verification_reference", "x" * 257),
        ("security_reviewer_reference", None),
    ],
)
def test_missing_or_malformed_reference_fails_closed(field, value):
    evidence = complete_evidence()
    object.__setattr__(evidence, field, value)
    assert field in missing_isolation_evidence(evidence)
    with pytest.raises(IsolationReadinessError):
        require_isolation_readiness(evidence)


def test_evidence_gate_does_not_accept_truthy_non_string_values():
    evidence = complete_evidence()
    object.__setattr__(evidence, "written_authorization_reference", True)
    assert "written_authorization_reference" in missing_isolation_evidence(evidence)
