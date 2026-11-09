# Phase 6.3 — read-only execution ledger API

**Status:** Implemented as a read-only visibility surface. It does not enable or perform execution.

## Endpoint

`GET /api/v1/playbooks/executions`

- Admin and analyst roles only; viewer access is denied.
- Supports optional exact execution `status` and `approval_id` filters.
- Uses bounded pagination (default 50, maximum 100; bounded offset).
- Orders deterministically by creation time and record ID.
- Returns only record ID, approval ID, fixed action/version, execution and compensation states, and lifecycle timestamps.

## Data minimization

The response intentionally excludes target identifiers, parameter digests, idempotency keys, provider references, internal summaries, credentials and raw provider payloads. Invalid status filters and out-of-range pagination are rejected.

## Safety boundary

This is a GET-only inspection route. It has no create, update, retry, claim, dispatch, provider, or compensation operation. `execution_enabled` remains false. The Wazuh adapter remains disabled and unregistered.


## Dashboard visibility

The overview now includes an admin/analyst-only execution ledger panel backed by this GET endpoint. It supports status filtering and bounded 25-record pagination, displays execution and compensation states with lifecycle timestamps, and provides an explicit read-only/disabled notice. It does not expose sensitive target, digest, idempotency or provider fields and has no action controls.
