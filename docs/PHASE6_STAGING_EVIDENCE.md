# Phase 6.4 staging evidence register

## Status

**Live Phase 6.4 staging evidence supplied:** none. This register is a template, not a claim that staging validation has run.

## Evidence rules

Use only an authorized staging deployment and disposable lab identities/events. Keep detailed records in restricted storage and link only sanitized references here. Never commit credentials, tokens, internal hostnames/IPs, raw events, incident titles, detection descriptions, resolution notes or provider payloads.

A green CI run, successful container build, mocked test, or local validator pass is not staging evidence. The offline validator compares supplied report JSON with independently authored expectations; it cannot authenticate the environment or prove source completeness. The evidence-register validator's default mode checks only Markdown structure. Its strict mode is an operator release gate and requires a complete, independently reviewed PASS.

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
| Reviewer decision (PASS / FAIL / BLOCKED) | Pending |
| Reviewer decision timestamp (UTC) | Pending |
| Follow-up issue/reference | Pending |

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

## Validate this register

Run from the repository root:

```powershell
# CI-safe structural check; this does not claim live validation.
python ops/validate-phase6-evidence.py

# Operator-only exit gate after every field and checklist item is completed.
# This succeeds only for a complete, independently reviewed PASS.
python ops/validate-phase6-evidence.py --require-exit
```

The strict command requires explicit UTC timestamps, a full deployed commit SHA, a validator commit with exit code 0, an explicit no-row-cap result, all checklist items checked, and an independent reviewer decision of PASS. FAIL or BLOCKED remains a valid recorded outcome but cannot satisfy the release gate. Do not weaken the gate or fill fields with illustrative values to obtain a zero exit code.
