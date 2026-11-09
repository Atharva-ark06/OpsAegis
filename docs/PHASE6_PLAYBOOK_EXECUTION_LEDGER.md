# Phase 6.3 — durable playbook execution ledger (foundation only)

**Status:** Implemented as a persistence and state-validation foundation. No execution or compensation endpoint exists.

## Scope

This increment adds a durable record shape for a future approved action attempt and its separate compensation lifecycle. It records the approval reference, fixed action/version, canonical target identifier, SHA-256 digest of normalized parameters, unique idempotency key, bounded state values, timestamps and optional sanitized provider reference/summary.

Raw action parameters, credentials, provider payloads and user-supplied URLs are not stored in this ledger.

## State model

Execution:

`pending → claimed → executing → succeeded | failed | outcome_unknown`

A known-unknown provider outcome can be reconciled to succeeded or failed only after a future independently verified reconciliation process. It cannot be blindly retried.

Compensation is independent:

`not_requested → requested → executing → succeeded | failed | outcome_unknown`

The database enforces allowed state values, unique idempotency keys and one action record per approval/action pair. Pure transition guards reject illegal transitions.

## Deliberate safety boundary

- No API route, worker, queue consumer, provider client, Wazuh request, or dispatch function is added.
- The Wazuh action remains disabled and unregistered.
- Approval records remain governance records and do not cause execution.
- This schema does not prove that Wazuh permissions, endpoint behavior, isolation state verification or rollback are safe.
- Do not populate this table manually to simulate successful actions.

## Required gates before any executor

1. Review the Wazuh isolation threat model and verify the deployed Wazuh version/API behavior.
2. Confirm minimum provider permissions and a dedicated credential through the operator's secret-management process.
3. Complete written authorization and disposable staging isolation/unisolation and rollback drills.
4. Design and independently review the executor's atomic approval claim, fencing, provider-state reconciliation, audit persistence and compensation handling.
5. Deliver the executor only in a separate PR with the adapter still disabled until explicit security approval.
