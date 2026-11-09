# Phase 6.4 staging validation

## Purpose and boundary

This runbook defines an operator-led comparison between the aggregate report endpoint and a known, bounded set of staging events. It does not create events, call providers, deploy the application, or prove that the supplied JSON came from staging. A successful local comparison is only one piece of evidence.

Do not use production data for this exercise. Use an authorized staging deployment, disposable lab identities, and a short UTC window. Keep Nuclei and Shannon disabled; neither is needed for reporting validation.

## Prerequisites

- Written authorization to use the named staging environment.
- A deployed OpsAegis version with the Phase 6.4 report endpoints and migration applied.
- An administrator/analyst account with access to the aggregate report endpoint.
- A disposable Wazuh test agent and a bounded test event plan; no real user or customer data.
- A restricted evidence location for detailed operator notes. Never commit raw events or provider payloads.

## Bounded test sequence

1. Record the staging environment alias, deployed commit/version, operator, UTC start/end, and the authorized change/test reference in the restricted evidence store.
2. Choose an explicit UTC window that contains only the test events. Confirm the report endpoint uses exactly that window:
   `GET /api/v1/reports/operations?since=<UTC>&until=<UTC>`
3. Run one known successful Wazuh Manager inventory collection and one deliberately failed collection using a controlled test condition approved for staging. Record expected terminal run counts and received/created/updated/skipped totals from the collection-run records.
4. Generate one known detection-to-incident path from a disposable authentication test event. Record the detection and incident creation timestamps from their persisted records. Calculate expected delay in seconds independently.
5. Resolve one test incident through the normal application workflow with a resolution note. Record its creation timestamp and first audited transition to resolved; calculate expected duration independently.
6. Export the aggregate report JSON for the exact same UTC window. Review it locally for accidental sensitive content before using it as validator input.
7. Create an operator-authored expected JSON file using the schema below. Values must come from the known test plan and restricted source records, not copied blindly from the report under test.
8. Run the comparison tool. Investigate every mismatch. If any report query reaches its 10,000-row cap, the comparison is inconclusive and the window must be narrowed.
9. Record the validator version/commit, exit code, sanitized result reference, expected/observed counts and timing differences. Update this evidence register only after a human reviewer confirms the underlying source records.

## Expected metrics file

Create a local JSON file with the exact window and the sources tested. Example shape (illustrative values only; not staging evidence):

```json
{
  "window": {
    "since": "2026-11-09T10:00:00Z",
    "until": "2026-11-09T12:00:00Z"
  },
  "collection": {
    "sources": {
      "wazuh-manager-agents": {
        "runs": 2,
        "successful_runs": 1,
        "failed_runs": 1,
        "failure_rate": 0.5,
        "received": 4,
        "created": 2,
        "updated": 1,
        "skipped": 1,
        "freshness": "fresh"
      }
    }
  },
  "response": {
    "detections_linked_to_incidents": 1,
    "mean_detection_to_incident_seconds": 300,
    "incidents_resolved": 1,
    "mean_incident_to_resolution_seconds": 1800
  }
}
```

The example is a schema illustration only. Replace every value and timestamp with values derived independently from your authorized staging test. Include all fields required by the validator for each source.

## Run the validator

From the repository root, save the sanitized response from the authenticated report endpoint as a local file and create the expected file above. Do not commit either file.

```powershell
python ops/validate-phase6-reporting.py --report artifacts/phase6-report.json --expected artifacts/phase6-expected.json
```

Exit codes: `0` means the supplied metrics matched; `1` means mismatches, missing data, or row-cap/incomplete results; `2` means input files could not be read as valid JSON. Exit code 0 does not independently prove staging identity, authorization, source completeness, or service health.\n\nAfter the report comparison, record the sanitized result in `docs/PHASE6_STAGING_EVIDENCE.md` and run the structural register check:\n\n```powershell\npython ops/validate-phase6-evidence.py\n```\n\nOnly after the operator and independent reviewer have verified every evidence item, completed every checklist item, and recorded a PASS should the strict gate be run:\n\n```powershell\npython ops/validate-phase6-evidence.py --require-exit\n```\n\nThe strict gate is a manual release check; CI must run structural mode only. Neither mode contacts staging or validates the underlying evidence.

## Sanitized evidence record

Record only:
- evidence ID and restricted artifact reference;
- environment alias (not hostname/IP), operator, UTC timestamp, deployed commit;
- exact report window and source names;
- expected/observed counts and timing differences;
- row-cap state, validator exit code and reviewer;
- pass/fail, limitations and follow-up issue.

Do not store bearer tokens, passwords, API keys, internal hostnames/IPs, raw Wazuh events, incident titles, detection descriptions, resolution notes or provider payloads in this repository.

## Acceptance criteria

- The report window exactly matches the independently defined UTC test window.
- Source collection counts and failure rate match the run records.
- Detection-to-incident and incident-to-resolution counts/timings match independently recorded timestamps within 0.01 seconds.
- No relevant query is row-capped; unknown/missing values are not treated as success.
- Evidence is sanitized, restricted, reviewed and linked by reference.
- Any discrepancy is investigated and documented; do not change expected values merely to make a report pass.
