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
