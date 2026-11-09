from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "ops" / "validate-phase6-evidence.py"
SPEC = spec_from_file_location("phase6_evidence_validation", SCRIPT)
MODULE = module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def register(*, decision="Pending", checked=False, row_cap="Pending"):
    marker = "x" if checked else " "
    values = {
        "Evidence ID": "Pending",
        "Environment alias": "Pending",
        "Operator / reviewer": "Pending",
        "UTC test timestamp": "Pending",
        "Deployed commit": "Pending",
        "Authorized change/test reference": "Pending",
        "Exact UTC report window": "Pending",
        "Sources exercised": "Pending",
        "Expected / observed collection counts": "Pending",
        "Expected / observed detection-to-incident timing": "Pending",
        "Expected / observed incident-to-resolution timing": "Pending",
        "Row-cap state": row_cap,
        "Validator commit and exit code": "Pending",
        "Sanitized restricted evidence reference": "Pending",
        "Reviewer decision (PASS / FAIL / BLOCKED)": decision,
        "Reviewer decision timestamp (UTC)": "Pending",
        "Follow-up issue/reference": "Pending",
    }
    if decision == "PASS":
        values.update({
            "Evidence ID": "EVIDENCE-2026-001",
            "Environment alias": "isolated-staging",
            "Operator / reviewer": "operator-1 / reviewer-1",
            "UTC test timestamp": "2026-11-09T10:00:00Z",
            "Deployed commit": "a" * 40,
            "Authorized change/test reference": "CHG-123",
            "Exact UTC report window": "2026-11-09T09:00:00Z to 2026-11-09T10:00:00Z",
            "Sources exercised": "wazuh-manager-agents; wazuh-indexer-alerts",
            "Expected / observed collection counts": "independently reconciled",
            "Expected / observed detection-to-incident timing": "independently reconciled",
            "Expected / observed incident-to-resolution timing": "independently reconciled",
            "Row-cap state": row_cap,
            "Validator commit and exit code": "b" * 40 + "; exit 0",
            "Sanitized restricted evidence reference": "vault://evidence/EVIDENCE-2026-001",
            "Reviewer decision (PASS / FAIL / BLOCKED)": "PASS",
            "Reviewer decision timestamp (UTC)": "2026-11-09T11:00:00Z",
            "Follow-up issue/reference": "None — no follow-up",
        })
    table = ["## Validation record", "", "| Field | Value |", "|---|---|"]
    table.extend(f"| {key} | {value} |" for key, value in values.items())
    checklist = [
        "Written staging authorization and disposable lab identities confirmed.",
        "Known successful and controlled failed collection runs recorded.",
        "Known detection-to-incident timestamps independently recorded.",
    ]
    return "\n".join(table + ["", "## Acceptance checklist", ""] + [f"- [{marker}] {item}" for item in checklist])


def test_template_register_passes_structure_only_without_claiming_live_evidence():
    assert MODULE.validate_register(register()) == []
    assert MODULE.validate_register(register(), require_exit=True)


def test_reviewed_pass_with_complete_evidence_satisfies_strict_gate():
    assert MODULE.validate_register(register(decision="PASS", checked=True, row_cap="no"), require_exit=True) == []


def test_blocked_or_failed_decision_cannot_satisfy_strict_gate():
    errors = MODULE.validate_register(register(decision="BLOCKED", checked=True, row_cap="no"), require_exit=True)
    assert any("decision of PASS" in error for error in errors)


def test_unchecked_acceptance_item_blocks_strict_gate():
    errors = MODULE.validate_register(register(decision="PASS", checked=False, row_cap="no"), require_exit=True)
    assert any("every acceptance checklist item" in error for error in errors)


def test_row_cap_and_malformed_timestamps_block_strict_gate():
    content = register(decision="PASS", checked=True, row_cap="yes").replace(
        "2026-11-09T10:00:00Z", "2026-11-09T10:00:00"
    )
    errors = MODULE.validate_register(content, require_exit=True)
    assert any("no-row-cap" in error for error in errors)
    assert any("UTC timestamp" in error for error in errors)


def test_missing_required_field_is_reported():
    content = register().replace("| Evidence ID | Pending |\n", "")
    assert any("Evidence ID" in error for error in MODULE.validate_register(content))
