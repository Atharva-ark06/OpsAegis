#!/usr/bin/env python3
"""Validate the Phase 6.4 evidence register without manufacturing staging proof.

Default mode checks the register's structure for CI. --require-exit is an
operator release gate and succeeds only after a reviewed PASS is recorded.
The tool never contacts OpsAegis, providers, or an evidence store.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
import sys

REQUIRED_FIELDS = (
    "Evidence ID",
    "Environment alias",
    "Operator / reviewer",
    "UTC test timestamp",
    "Deployed commit",
    "Authorized change/test reference",
    "Exact UTC report window",
    "Sources exercised",
    "Expected / observed collection counts",
    "Expected / observed detection-to-incident timing",
    "Expected / observed incident-to-resolution timing",
    "Row-cap state",
    "Validator commit and exit code",
    "Sanitized restricted evidence reference",
    "Reviewer decision (PASS / FAIL / BLOCKED)",
    "Reviewer decision timestamp (UTC)",
    "Follow-up issue/reference",
)
PLACEHOLDERS = {"", "pending", "tbd", "todo", "not recorded", "unknown"}


def _table_rows(markdown: str, heading: str) -> list[list[str]]:
    lines = markdown.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    except StopIteration:
        return []
    rows: list[list[str]] = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(not cell or set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows


def _utc_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def validate_register(markdown: str, *, require_exit: bool = False) -> list[str]:
    errors: list[str] = []
    rows = _table_rows(markdown, "## Validation record")
    if not rows:
        return ["Validation record table is missing or empty."]

    fields: dict[str, str] = {}
    for row in rows:
        if len(row) != 2:
            errors.append("Validation record rows must contain exactly two columns.")
            continue
        key, value = row
        if key.lower() == "field":
            continue
        if key in fields:
            errors.append(f"Duplicate validation field: {key}")
        fields[key] = value

    for field in REQUIRED_FIELDS:
        if field not in fields:
            errors.append(f"Required validation field is missing: {field}")

    checklist = [
        line.strip()
        for line in markdown.splitlines()
        if line.strip().startswith("- [ ]") or line.strip().startswith("- [x]") or line.strip().startswith("- [X]")
    ]
    if not checklist:
        errors.append("Acceptance checklist is missing or empty.")

    if not require_exit:
        return errors

    for field in REQUIRED_FIELDS:
        value = fields.get(field, "").strip()
        if value.lower() in PLACEHOLDERS:
            errors.append(f"Strict exit requires a recorded value for: {field}")

    decision = fields.get("Reviewer decision (PASS / FAIL / BLOCKED)", "").strip().upper()
    if decision != "PASS":
        errors.append("Strict exit requires an independent reviewer decision of PASS.")

    if not _utc_timestamp(fields.get("UTC test timestamp", "").strip()):
        errors.append("UTC test timestamp must be an ISO-8601 UTC timestamp.")
    if not _utc_timestamp(fields.get("Reviewer decision timestamp (UTC)", "").strip()):
        errors.append("Reviewer decision timestamp must be an ISO-8601 UTC timestamp.")

    commit = fields.get("Deployed commit", "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        errors.append("Deployed commit must be a full 40-character Git SHA.")

    validator = fields.get("Validator commit and exit code", "").strip()
    if not re.search(r"(?i)\bexit\s*[:=]?\s*0\b", validator) or not re.search(r"\b[0-9a-fA-F]{7,40}\b", validator):
        errors.append("Validator record must include a commit SHA and exit code 0.")

    row_cap = fields.get("Row-cap state", "").strip().lower()
    if row_cap not in {"no", "false", "not reached", "none", "0"}:
        errors.append("Strict exit requires an explicit no-row-cap result.")

    if any(not line.startswith("- [x]") and not line.startswith("- [X]") for line in checklist):
        errors.append("Strict exit requires every acceptance checklist item to be checked.")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--register",
        type=Path,
        default=Path("docs/PHASE6_STAGING_EVIDENCE.md"),
        help="Markdown evidence register (default: docs/PHASE6_STAGING_EVIDENCE.md)",
    )
    parser.add_argument(
        "--require-exit",
        action="store_true",
        help="Require a fully recorded, independently reviewed PASS; intended for operator use only.",
    )
    args = parser.parse_args()
    try:
        markdown = args.register.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Unable to read evidence register: {type(exc).__name__}", file=sys.stderr)
        return 2

    errors = validate_register(markdown, require_exit=args.require_exit)
    if errors:
        for error in errors:
            print(f"BLOCKED: {error}", file=sys.stderr)
        return 1

    if args.require_exit:
        print("Phase 6.4 evidence register records a reviewed PASS.")
    else:
        print("Phase 6.4 evidence register structure is valid; live staging evidence is not implied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
