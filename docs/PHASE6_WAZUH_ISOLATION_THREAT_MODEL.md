# Wazuh agent-isolation adapter threat model (draft)

**Status:** Design-only draft. Not an implementation approval.  
**Scope:** Future `wazuh.agent_isolate` and compensating `wazuh.agent_unisolate` actions.  
**Current system state:** The action catalogue is descriptive only. No provider adapter or execution endpoint is registered or enabled. This document does not change that state.

## 1. Security objective and non-goals

The objective is to define the conditions under which an explicitly approved operator could request isolation of one registered Wazuh agent, verify the provider's result, and attempt a separately audited compensating unisolation.

This design does **not** authorize autonomous containment, bulk isolation, arbitrary host/network blocking, shell execution, scanner invocation, or production use. It does not assert that a particular Wazuh API role or endpoint is sufficient; those details must be verified against the deployed Wazuh version and a disposable staging manager before implementation.

## 2. Assets and security objectives

| Asset | Required protection |
|---|---|
| Wazuh Manager credentials / tokens | Backend-only, least privilege, rotation, never logged or returned |
| Agent identity and membership | Bind action to a canonical registered agent ID; reject unknown, manager, deleted, or ambiguous targets |
| Approval record | Immutable requester/approver separation, expiry, exact action and target binding |
| Idempotency key | Stable, unique to approval + action + target + canonical parameters |
| Provider state | Prevent duplicate or cross-target action; verify observed state after request |
| Audit trail | Record who requested, approved, executed, verified and compensated; redact secrets |
| OpsAegis API and workers | Authenticated, authorized, bounded, resilient to retries and worker loss |

Security objectives: authorization, target integrity, availability, traceability, confidentiality of credentials, and recoverability from mistaken isolation.

## 3. Trust boundaries and intended data flow

1. An authenticated administrator or analyst creates an approval request for one exact registered agent and a fixed action identifier.
2. A different active authorized operator approves or rejects it. Approval is single-use and expires.
3. The execution service re-reads the approval, requester, approver, agent record and current action policy from the database immediately before any provider call.
4. A backend-only adapter uses a fixed configured Wazuh Manager origin and a dedicated least-privilege service identity. No caller-supplied URL, command, script, agent name, IP address or arbitrary provider path is accepted.
5. The adapter sends one bounded request for the canonical agent ID, records a sanitized provider reference, and independently verifies the resulting state where the supported Wazuh version permits it.
6. A separately authorized compensation request targets the same agent and approval lineage. Compensation is a new audited action, not an assumed rollback.

The browser never receives provider credentials or access tokens. The API must not proxy arbitrary provider requests.

## 4. Threat analysis and required controls

| Threat | Example / impact | Required control before enablement |
|---|---|---|
| Spoofed or stale target | A caller substitutes an agent ID after approval | Bind canonical agent ID and immutable agent record to approval; revalidate existence and eligibility immediately before execution |
| Privilege escalation | Analyst or compromised account invokes containment | Enforce role checks server-side; require a different active approver; deny self-approval; re-check both users at execution |
| Approval replay | Repeated request isolates an endpoint multiple times | Atomic single-use approval transition; expiry check; deterministic idempotency key; unique DB constraint / execution ledger |
| TOCTOU race | Agent membership or approval changes between check and provider call | Transactional claim/fencing token; re-read target and approval at execution; reject stale versions |
| SSRF / arbitrary command | User supplies manager URL, script or active-response command | Fixed HTTPS base URL from trusted configuration; fixed adapter operation; no arbitrary URL/command/headers/body fields |
| Credential theft | Token appears in logs, exception, response or evidence | Dedicated service account; secret manager/environment injection; redact auth headers and provider bodies; rotate credentials; no token persistence |
| Over-broad blast radius | Bulk or manager isolation causes outage | Exactly one registered endpoint per approval; reject special manager ID and wildcard/bulk selectors; enforce explicit denylist and maximum one target |
| Provider/API ambiguity | Timeout occurs after Wazuh applied action | Treat timeout as **unknown outcome**, not failure-safe; query provider state before retry; never blindly repeat non-idempotent requests |
| Partial failure | Isolation succeeds but audit write fails, or vice versa | Durable execution intent before call; append result after; reconciliation state for uncertain outcomes; never report success without persisted audit |
| Compensation failure | Unisolation is rejected or times out | Separate compensation status; alert operator through existing internal workflow; preserve isolated/unknown state; never claim rollback without provider confirmation |
| Compromised worker | Worker replays or changes target | Server-side approval validation, fencing, least privilege, fixed operation, idempotency and append-only audit |
| Sensitive audit leakage | Agent IPs, tokens or raw provider payload exposed | Store only canonical internal IDs, action/status, timestamps and sanitized provider reference; restrict audit read access |

## 5. Authorization and provider identity requirements

Before adapter work, the operator must verify and document (without committing secrets):

- Exact Wazuh Manager version and the vendor-supported isolation/unisolation mechanism for that version.
- The minimum API role/permissions required for the specific operation and for independent state verification. Do not reuse a broad administrator credential by convenience.
- Whether the provider operation is idempotent, how duplicate requests behave, and what response means “accepted” versus “completed.”
- Whether the provider supports a reliable state query and what state proves isolation or unisolation.
- Token lifetime, revocation, TLS trust chain, network source restrictions and credential rotation procedure.
- Whether the operation affects only the intended endpoint or can affect shared infrastructure.

If Wazuh cannot provide a narrowly scoped identity or reliable target/state verification, the adapter remains disabled.

## 6. Execution state machine requirements

A future implementation must use explicit persisted states, at minimum:

`pending_approval → approved → claimed → executing → succeeded | failed | outcome_unknown`

Compensation must be tracked separately:

`not_requested → requested → executing → succeeded | failed | outcome_unknown`

- Approval is bound to the exact action version, canonical target, normalized parameters and expiry.
- Claiming is atomic and single-use. A worker lease/fencing token prevents stale workers from finalizing a newer attempt.
- Enforce the existing 1–30 second adapter timeout and bounded retry policy. Do not automatically retry an operation whose provider outcome is unknown.
- Persist an execution intent before the provider call and a sanitized result after it.
- Success requires a provider response plus independent state verification. HTTP acceptance alone is not proof of isolation.
- A timeout, malformed response, verification mismatch or lost lease results in `outcome_unknown` or a safe failure state requiring reconciliation—not a fabricated success.
- Compensation requires a distinct explicit authorization and must verify the final unisolated state. It must not silently run as an automatic rollback.

## 7. Staging-only validation and rollback drill

No live validation is claimed. Before any production consideration, an authorized operator must complete all of the following in an isolated staging environment with a disposable, non-critical agent:

1. Record written authorization, Wazuh version, deployed OpsAegis commit, test window and reviewer.
2. Verify the dedicated service identity cannot perform unrelated administrative operations.
3. Test rejection for unknown, deleted, manager, wildcard and mismatched agent IDs.
4. Test requester self-approval, expired approval, rejected approval, replay, duplicate delivery and concurrent execution.
5. Isolate exactly one disposable agent; independently query and record the provider state.
6. Exercise timeout/connection-loss after request submission and prove reconciliation does not blindly repeat the action.
7. Execute a separately approved unisolation; independently verify restored connectivity/state.
8. Test worker restart/lease loss, provider unavailability and audit persistence failure handling.
9. Confirm logs, API responses, audit records and evidence exports contain no credentials or raw provider payloads.
10. Have a reviewer verify the sanitized evidence and explicitly approve or reject the next implementation gate.

Never run this drill against production or a real user endpoint.

## 8. Hard stop conditions

Keep the adapter unregistered and disabled if any of these is true:

- No written authorization or disposable staging target.
- Provider version/API behavior or minimum permissions are unknown.
- Credentials require broad administrator privileges.
- Target cannot be bound to one canonical registered agent.
- Independent verification is unavailable.
- Duplicate/replay behavior is not understood.
- Compensation cannot be tested and independently verified.
- Audit persistence, approval separation, fencing or secret redaction is incomplete.
- Any test unexpectedly affects a non-test endpoint.

## 9. Current decision

**Decision: NOT APPROVED FOR IMPLEMENTATION OR ENABLEMENT.**

This draft is a preparation artifact only. Required next gates are operator/security review, version-specific Wazuh API and permission verification, least-privilege credential provisioning, and authorized staging evidence. Until all gates pass in a separately reviewed change, `wazuh.agent_isolate` remains catalogue metadata with `enabled: false` and `adapter_registered: false`.
