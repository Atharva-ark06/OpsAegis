#!/usr/bin/env python3
"""Validate the Phase 5 evidence register without inventing live validation.

Default mode checks the Markdown matrix structure and required workstreams.
--require-exit is a manual release gate: every row must have recorded staging/
production validation or an explicitly accepted not-configured/out-of-scope
disposition. CI must not use --require-exit because it has no access to the
operator's restricted staging evidence.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

REQUIRED_WORKSTREAMS = (
    "Wazuh Manager agent inventory",
    "Wazuh Indexer alerts",
    "Wazuh Vulnerability Detector",
    "CrowdSec LAPI",
    "Nuclei isolated worker",
    "Shannon bridge",
    "Redis detection scheduler",
    "End-to-end detection",
    "Authentication / RBAC / secrets / API perimeter",
    "Docker deployment / migrations / storage",
    "PostgreSQL backup and restore",
    "Off-host retention / RPO / RTO",
)

EXIT_DISPOSITIONS = (
    "staging-validated",
    "production-validated",
    "not configured - accepted",
    "not-configured-accepted",
    "out of scope - accepted",
    "out-of-scope-accepted",
)


def parse_validation_rows(markdown: str) -> list[tuple[str, str]]:
    """Return (workstream, status) rows from the Phase 5 validation matrix."""
    lines = markdown.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "## Validation matrix")
    except StopIteration:
        return []

    rows: list[tuple[str, str]] = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0].lower() == "workstream":
            continue
        if all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append((cells[0], cells[3]))
    return rows


def validate_evidence_register(markdown: str, *, require_exit: bool = False) -> list[str]:
    rows = parse_validation_rows(markdown)
    errors: list[str] = []
    if not rows:
        return ["Validation matrix is missing or contains no four-column workstream rows."]

    names = [name for name, _ in rows]
    for required in REQUIRED_WORKSTREAMS:
        if not any(required.lower() in name.lower() for name in names):
            errors.append(f"Required workstream is missing: {required}")

    for name, status in rows:
        if not status:
            errors.append(f"Workstream has an empty status: {name}")
        if require_exit and not any(disposition in status.lower() for disposition in EXIT_DISPOSITIONS):
            errors.append(f"Workstream has no accepted live/out-of-scope exit evidence: {name} [{status}]")

    if require_exit and "live environment evidence supplied for this register: none" in markdown.lower():
        errors.append("Register still declares that no live environment evidence has been supplied.")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "PHASE5_STAGING_EVIDENCE.md",
        help="Path to the Phase 5 Markdown evidence register.",
    )
    parser.add_argument(
        "--require-exit",
        action="store_true",
        help="Fail unless every workstream has staging/production evidence or an accepted exclusion.",
    )
    args = parser.parse_args()
    try:
        markdown = args.file.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Unable to read evidence register: {exc}", file=sys.stderr)
        return 2

    errors = validate_evidence_register(markdown, require_exit=args.require_exit)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if args.require_exit:
        print("Phase 5 exit evidence is structurally complete. Review evidence references before sign-off.")
    else:
        print("Phase 5 evidence register structure is valid; live Phase 5 exit is not asserted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
