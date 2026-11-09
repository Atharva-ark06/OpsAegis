from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "ops" / "validate-phase5-evidence.py"
SPEC = spec_from_file_location("phase5_evidence", SCRIPT)
MODULE = module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def matrix(status="Pending"):
    rows = "\n".join(
        f"| {name} | Implemented | Record live evidence | {status} |"
        for name in MODULE.REQUIRED_WORKSTREAMS
    )
    return (
        "# Evidence\n\n## Validation matrix\n"
        "| Workstream | Implementation | Required live evidence | Current status |\n"
        "|---|---|---|---|\n"
        f"{rows}\n"
    )


def test_register_structure_accepts_complete_workstream_matrix():
    assert MODULE.validate_evidence_register(matrix()) == []


def test_register_rejects_missing_required_workstream():
    text = matrix().replace("| CrowdSec LAPI | Implemented | Record live evidence | Pending |\n", "")
    errors = MODULE.validate_evidence_register(text)
    assert any("CrowdSec LAPI" in error for error in errors)


def test_exit_gate_rejects_pending_live_evidence():
    errors = MODULE.validate_evidence_register(matrix(), require_exit=True)
    assert len(errors) == len(MODULE.REQUIRED_WORKSTREAMS)


def test_exit_gate_accepts_documented_staging_and_accepted_exclusions():
    text = matrix("Staging-validated — evidence: EVID-123")
    text = text.replace(
        "| Nuclei isolated worker | Implemented | Record live evidence | Staging-validated |",
        "| Nuclei isolated worker | Implemented | Explicitly excluded | Out of scope - accepted |",
    )
    text = text.replace(
        "| Shannon bridge | Implemented | Explicitly excluded | Not configured - accepted; accepted: DEC-002 |",
        "| Shannon bridge | Implemented | Explicitly excluded | Not configured - accepted |",
    )
    assert MODULE.validate_evidence_register(text, require_exit=True) == []


def test_exit_gate_does_not_treat_no_evidence_declaration_as_complete():
    text = matrix("Staging-validated — evidence: EVID-123") + "\nLive environment evidence supplied for this register: none\n"
    assert any("no live environment evidence" in error.lower()
               for error in MODULE.validate_evidence_register(text, require_exit=True))


def test_exit_gate_requires_evidence_reference_for_validated_workstream():
    errors = MODULE.validate_evidence_register(matrix("Staging-validated"), require_exit=True)
    assert any("evidence reference" in error.lower() for error in errors)


def test_exit_gate_requires_acceptance_reference_for_exclusions():
    text = matrix("Staging-validated — evidence: EVID-123").replace(
        "| Nuclei isolated worker | Implemented | Record live evidence | Staging-validated — evidence: EVID-123 |",
        "| Nuclei isolated worker | Implemented | Explicitly excluded | Out of scope - accepted |",
    )
    errors = MODULE.validate_evidence_register(text, require_exit=True)
    assert any("acceptance reference" in error.lower() for error in errors)
