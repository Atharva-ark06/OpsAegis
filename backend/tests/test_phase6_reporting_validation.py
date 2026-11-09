from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "ops" / "validate-phase6-reporting.py"
SPEC = spec_from_file_location("phase6_reporting_validation", SCRIPT)
MODULE = module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def sample():
    return (
        {
            "generated_at": "2026-11-09T12:00:00+00:00",
            "window": {"since": "2026-11-09T10:00:00+00:00", "until": "2026-11-09T12:00:00+00:00", "timezone": "UTC"},
            "collection": {
                "rows_limited": False,
                "sources": [
                    {"source": "wazuh-manager-agents", "runs": 2, "successful_runs": 2, "failed_runs": 0,
                     "failure_rate": 0.0, "received": 4, "created": 2, "updated": 1, "skipped": 1, "freshness": "fresh"}
                ],
            },
            "response": {
                "rows_limited": False,
                "detections_linked_to_incidents": 1,
                "mean_detection_to_incident_seconds": 300.0,
                "incidents_resolved": 1,
                "mean_incident_to_resolution_seconds": 1800.0,
            },
            "data_quality": {"limitations": ["persisted records only"]},
        },
        {
            "window": {"since": "2026-11-09T10:00:00Z", "until": "2026-11-09T12:00:00Z"},
            "collection": {
                "sources": {
                    "wazuh-manager-agents": {
                        "runs": 2, "successful_runs": 2, "failed_runs": 0, "failure_rate": 0.0,
                        "received": 4, "created": 2, "updated": 1, "skipped": 1, "freshness": "fresh"
                    }
                }
            },
            "response": {
                "detections_linked_to_incidents": 1,
                "mean_detection_to_incident_seconds": 300,
                "incidents_resolved": 1,
                "mean_incident_to_resolution_seconds": 1800,
            },
        },
    )


def test_known_staging_metrics_match_report():
    report, expected = sample()
    assert MODULE.validate_report(report, expected) == []


def test_metric_mismatch_is_reported_without_dumping_payload():
    report, expected = sample()
    expected["response"]["mean_detection_to_incident_seconds"] = 120
    errors = MODULE.validate_report(report, expected)
    assert any("mean_detection_to_incident_seconds" in error for error in errors)
    assert not any("sensitive" in error.lower() for error in errors)


def test_row_cap_makes_comparison_inconclusive():
    report, expected = sample()
    report["collection"]["rows_limited"] = True
    assert any("row cap" in error.lower() for error in MODULE.validate_report(report, expected))


def test_report_window_must_be_explicit_utc():
    report, expected = sample()
    report["window"]["since"] = "2026-11-09T10:00:00"
    assert any("explicit UTC" in error for error in MODULE.validate_report(report, expected))


def test_missing_source_and_quality_limitations_fail_closed():
    report, expected = sample()
    report["collection"]["sources"] = []
    report["data_quality"] = {}
    errors = MODULE.validate_report(report, expected)
    assert any("source is missing" in error for error in errors)
    assert any("limitations are missing" in error for error in errors)
