# Phase 6.4 staging evidence register

## Status

**Live Phase 6.4 staging evidence supplied:** none. This register is a template, not a claim that staging validation has run.

## Evidence rules

Use only an authorized staging deployment and disposable lab identities/events. Keep detailed records in restricted storage and link only sanitized references here. Never commit credentials, tokens, internal hostnames/IPs, raw events, incident titles, detection descriptions, resolution notes or provider payloads.

A green CI run, successful container build, mocked test, or local validator pass is not staging evidence. The offline validator compares supplied report JSON with independently authored expectations; it cannot authenticate the environment or prove source completeness.

## Validation record

| Field | Value |
|---|---|
| Evidence ID | Pending |
| Environment alias | Pending |
| Operator / reviewer | Pending |
| UTC test timestamp | Pending |
| Deployed commit | Pending |
| Authorized change/test reference | Pending |
| Exact UTC report window | Pending |
| Sources exercised | Pending |
| Expected / observed collection counts | Pending |
| Expected / observed detection-to-incident timing | Pending |
| Expected / observed incident-to-resolution timing | Pending |
| Row-cap state | Pending |
| Validator commit and exit code | Pending |
| Sanitized restricted evidence reference | Pending |
| Outcome / follow-up issue | Pending |

## Acceptance checklist

- [ ] Written staging authorization and disposable lab identities confirmed.
- [ ] Known successful and controlled failed collection runs recorded.
- [ ] Known detection-to-incident timestamps independently recorded.
- [ ] Known incident creation and first audited resolution timestamps independently recorded.
- [ ] Aggregate report exported for the exact UTC window and reviewed for sensitive content.
- [ ] Expected metrics authored independently from source records.
- [ ] Offline validator passes with no row caps or missing values.
- [ ] A reviewer verifies the source records and sanitized evidence reference.
- [ ] Only then update the Phase 6.4 roadmap status; do not mark a CI-only or local-only check as staging-validated.
