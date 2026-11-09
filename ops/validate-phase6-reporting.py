#!/usr/bin/env python3
"""Compare a sanitized Phase 6.4 report export with operator-known staging expectations.

This tool validates a supplied report; it does not call OpsAegis, connect to providers,
create test events, or establish that a report came from a trusted environment.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys
from typing import Any

SOURCE_METRICS = (
    "runs", "successful_runs", "failed_runs", "failure_rate",
    "received", "created", "updated", "skipped", "freshness",
)
RESPONSE_METRICS = (
    "detections_linked_to_incidents",
    "mean_detection_to_incident_seconds",
    "incidents_resolved",
    "mean_incident_to_resolution_seconds",
)


def _utc_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp with an explicit UTC offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must use UTC (Z or +00:00)")
    return parsed.astimezone(timezone.utc)


def _same_value(actual: Any, expected: Any) -> bool:
    if expected is None or isinstance(expected, (str, bool)):
        return actual == expected
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        if not isinstance(actual, (int, float)) or isinstance(actual, bool):
            return False
        return math.isclose(float(actual), float(expected), rel_tol=0.0, abs_tol=0.01)
    return actual == expected


def validate_report(report: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    """Return bounded metric mismatches without printing raw report data."""
    errors: list[str] = []
    if not isinstance(report, dict) or not isinstance(expected, dict):
        return ["Report and expected values must both be JSON objects."]

    report_window = report.get("window")
    expected_window = expected.get("window")
    if not isinstance(report_window, dict) or not isinstance(expected_window, dict):
        errors.append("Both report and expected file must include a window object.")
    else:
        if report_window.get("timezone") != "UTC":
            errors.append("Report window timezone must be UTC.")
        for key in ("since", "until"):
            try:
                actual_time = _utc_datetime(report_window.get(key), f"report.window.{key}")
                expected_time = _utc_datetime(expected_window.get(key), f"expected.window.{key}")
                if actual_time != expected_time:
                    errors.append(f"window.{key}: expected {expected_time.isoformat()}, observed {actual_time.isoformat()}")
            except ValueError as exc:
                errors.append(str(exc))

    generated_at = report.get("generated_at")
    if generated_at is not None:
        try:
            _utc_datetime(generated_at, "report.generated_at")
        except ValueError as exc:
            errors.append(str(exc))

    collection = report.get("collection")
    if not isinstance(collection, dict):
        errors.append("Report collection section is missing.")
        collection = {}
    if collection.get("rows_limited") is True:
        errors.append("Collection query reached the row cap; comparison is inconclusive.")
    source_rows = collection.get("sources")
    if not isinstance(source_rows, list):
        errors.append("Report collection.sources must be an array.")
        source_rows = []
    sources: dict[str, dict[str, Any]] = {}
    for row in source_rows:
        if not isinstance(row, dict) or not isinstance(row.get("source"), str):
            errors.append("Report contains a source row without a source identifier.")
            continue
        if row["source"] in sources:
            errors.append(f"Report contains duplicate source row: {row['source']}")
        sources[row["source"]] = row

    expected_collection = expected.get("collection")
    expected_sources = expected_collection.get("sources") if isinstance(expected_collection, dict) else None
    if not isinstance(expected_sources, dict) or not expected_sources:
        errors.append("Expected file must define collection.sources with at least one known source.")
    else:
        for source, metrics in expected_sources.items():
            if not isinstance(source, str) or not isinstance(metrics, dict):
                errors.append("Each expected collection source must map to a metrics object.")
                continue
            actual = sources.get(source)
            if actual is None:
                errors.append(f"collection.{source}: source is missing from the report.")
                continue
            for metric in SOURCE_METRICS:
                if metric not in metrics:
                    errors.append(f"expected.collection.{source}.{metric} is required.")
                    continue
                if not _same_value(actual.get(metric), metrics[metric]):
                    errors.append(
                        f"collection.{source}.{metric}: expected {metrics[metric]!r}, observed {actual.get(metric)!r}"
                    )

    response = report.get("response")
    if not isinstance(response, dict):
        errors.append("Report response section is missing.")
        response = {}
    if response.get("rows_limited") is True:
        errors.append("Response metric query reached the row cap; comparison is inconclusive.")
    expected_response = expected.get("response")
    if not isinstance(expected_response, dict):
        errors.append("Expected file must define a response object.")
    else:
        for metric in RESPONSE_METRICS:
            if metric not in expected_response:
                errors.append(f"expected.response.{metric} is required.")
                continue
            if not _same_value(response.get(metric), expected_response[metric]):
                errors.append(
                    f"response.{metric}: expected {expected_response[metric]!r}, observed {response.get(metric)!r}"
                )

    data_quality = report.get("data_quality")
    if not isinstance(data_quality, dict) or not isinstance(data_quality.get("limitations"), list):
        errors.append("Report data_quality limitations are missing; reviewability cannot be established.")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="Sanitized JSON from GET /api/v1/reports/operations")
    parser.add_argument("--expected", type=Path, required=True, help="Operator-authored expected metrics JSON")
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        expected = json.loads(args.expected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Unable to read valid JSON input: {exc}", file=sys.stderr)
        return 2

    errors = validate_report(report, expected)
    if errors:
        for error in errors:
            print(f"MISMATCH: {error}", file=sys.stderr)
        print("Phase 6.4 staging comparison FAILED; do not record a pass.", file=sys.stderr)
        return 1

    print("Phase 6.4 report metrics match the supplied operator expectations.")
    print("This comparison alone does not prove environment identity, authorization, or live-service health.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
