# Phase 6 — Wazuh recovery and staging validation runbook

**Implementation status:** Recovery guidance and operator procedures only.  
**Live validation status:** NOT PERFORMED / NO EVIDENCE RECORDED.  
**Provider action status:** Wazuh isolation and unisolation remain disabled and unregistered.

This runbook combines the recovery, staging-validation and dashboard work planned for PRs #86–#88. It does not approve or implement a Wazuh mutation adapter.

## 1. Non-negotiable safety boundary

- Do not test against production, a real user endpoint, a manager node, or a shared/critical agent.
- Use only an isolated staging Manager and one disposable, non-critical agent covered by written authorization.
- Confirm the exact deployed Wazuh Manager version and version-specific supported API behavior before testing.
- Use a dedicated least-privilege identity. Do not reuse a broad administrator credential.
- Never put API keys, JWTs, passwords, private keys, raw provider payloads, agent IPs, or personal data in this evidence register or source control.
- Do not treat an HTTP acceptance response, a ledger status, or a dashboard label as proof of provider state.
- Do not retry a request after a timeout or lost connection until the actual provider state is independently reconciled.
- Unisolation is a separate, explicitly approved operation. It is not an automatic rollback and must be independently verified.
- Stop immediately if a test touches an unintended agent or the provider's target/state cannot be established.

The current OpsAegis repository has no Wazuh isolation/unisolation dispatcher or mutation endpoint. The dashboard is read-only. A `requested`, `executing`, or `succeeded` compensation ledger value is not evidence that a provider request was sent or completed.

## 2. Entry criteria

An authorized operator and independent security reviewer must confirm all of the following before a staging drill:

1. Written authorization names the staging environment, exact disposable target, permitted operations, test window and stop contact.
2. The Manager and Indexer versions are recorded, and the relevant vendor API documentation matches the deployed version.
3. The test target is a disposable agent, not the Manager, not a production asset and not shared infrastructure.
4. The service identity's permissions are reviewed and limited to the minimum required operations and state verification.
5. TLS verification, trusted CA configuration, network boundaries and credential handling are reviewed.
6. The target identity can be independently queried and unambiguously bound to the authorized disposable agent.
7. A separate unisolation approval path and an operator recovery contact are available.
8. The reviewer has accepted the test plan and evidence-redaction procedure.

If any entry criterion is absent, record the gate as BLOCKED and do not issue a mutation request.

## 3. Staging drill sequence

Run each step only after the preceding step is reviewed. Record expected and observed results separately.

| Step | Test | Expected safe result |
|---|---|---|
| 1 | Record deployed OpsAegis commit, Wazuh versions, environment and approved test window | Exact versions and authorization are traceable |
| 2 | Verify the disposable target using a read-only provider query | One exact, eligible staging agent is identified |
| 3 | Try unknown, deleted, Manager, wildcard, stale and substituted target identifiers in the test harness | Every invalid or mismatched target is rejected before provider mutation |
| 4 | Exercise requester self-approval, expired approval, rejected approval and approval replay | Each is rejected and audit events are recorded |
| 5 | Exercise duplicate delivery and concurrent claims for the same approval/action/target | At most one valid claim proceeds; duplicates are rejected safely |
| 6 | Exercise connection loss/timeout after a simulated or authorized request submission | State becomes outcome-unknown; no blind automatic retry occurs |
| 7 | Exercise worker restart/lease loss and audit persistence failure in the isolated test harness | Stale workers cannot finalize; uncertain outcomes remain visible and are reconciled |
| 8 | Under separate written approval, isolate only the disposable staging agent | Provider state is independently queried; HTTP acceptance alone is insufficient |
| 9 | Under a distinct unisolation approval, request unisolation of that same target | Provider state is independently queried and confirms the agent is no longer isolated |
| 10 | Review API responses, logs, audit events and evidence exports | No credentials, raw provider payloads or unnecessary personal data are exposed |
| 11 | Independent reviewer examines all sanitized artifacts and signs a decision | PASS, FAIL or BLOCKED is explicitly recorded; no implied approval |

Do not perform steps 8–9 using this repository's current application: no mutation adapter is registered. Those provider drills require a separately authorized test harness or a future independently reviewed implementation.

## 4. Recovery decision procedure

### Execution state is `outcome_unknown`

1. Stop retries. Do not mark the action failed or succeeded based on the timeout.
2. Query the provider using the approved read-only state-verification procedure.
3. If provider state is still ambiguous or unavailable, preserve `outcome_unknown`, escalate to the operator and do not issue another mutation.
4. If provider state is confirmed, record the sanitized evidence and have the reviewer reconcile the ledger through the separately approved process.

### Execution state is `succeeded`

1. Do not assume the endpoint is safe or reachable merely because the execution ledger says succeeded.
2. If recovery is required, create a distinct approval for the exact same disposable target and the fixed unisolation action.
3. Verify the provider's unisolated state independently before closing the recovery record.

### Execution state is `failed`

A failed request does not prove that the provider made no change. Check provider state before deciding whether recovery is needed. Never infer "not isolated" from a failure code alone.

### Compensation state is `failed` or `outcome_unknown`

Stop automated retries. Reconcile actual provider state, preserve the audit trail, contact the named operator and follow the approved manual recovery procedure. Do not claim rollback succeeded until provider state has been independently verified.

### Compensation state is `requested` or `executing`

This repository has no compensation dispatcher. These ledger values are lifecycle labels only; they do not prove that an external request was issued. An operator must review the associated evidence and implementation boundary.

## 5. Evidence register template

Keep the completed register and artifacts in the organization's approved evidence store, not in Git. Commit only this blank template or sanitized aggregate metadata if organizational policy explicitly permits it.

| Field | Value |
|---|---|
| Evidence record ID | |
| Written authorization / change reference | |
| Environment identifier | |
| Test window (UTC) | |
| Operator and role | |
| Independent reviewer | |
| OpsAegis commit SHA | |
| Wazuh Manager version | |
| Wazuh Indexer version | |
| Version-specific API reference | |
| Disposable agent reference (non-sensitive) | |
| Service identity / least-privilege review reference | |
| Provider-state verification method | |
| Isolation drill result and evidence reference | |
| Separate unisolation approval reference | |
| Unisolation verification result and evidence reference | |
| Timeout / outcome-unknown test reference | |
| Replay / duplicate / concurrency test reference | |
| Worker-loss / audit-persistence test reference | |
| Secret-redaction review reference | |
| Overall decision (PASS / FAIL / BLOCKED) | |
| Reviewer decision timestamp (UTC) | |
| Follow-up actions | |

Do not fill this template with invented or example evidence. Blank fields mean evidence is not recorded.

## 6. Acceptance and stop conditions

A staging drill is acceptable only when every required entry criterion and test has a reviewed, sanitized evidence reference, the disposable agent is confirmed restored to its expected state, and the independent reviewer records PASS.

Record FAIL for an unexpected target, missing audit event, unverified state, permission overreach, secret exposure, unsafe retry, or failed recovery. Record BLOCKED when authorization, version/API compatibility, least privilege, disposable staging, or independent verification is unavailable.

A PASS in this runbook is evidence for the exact staging environment and tested commit only. It does not authorize production use or automatically approve a future adapter.

## 7. Current repository status

- The execution ledger API remains GET-only and role restricted.
- Recovery guidance is derived from persisted execution/compensation statuses and is informational only.
- Unknown outcomes explicitly instruct operators to stop and reconcile rather than retry.
- No provider mutation, isolation, unisolation, dispatch, queue consumer, worker, or enablement setting is added.
- No live Wazuh staging drill has been performed by this PR. Evidence remains NOT RECORDED.
- The Wazuh action remains disabled and unregistered pending independent review and a separately scoped implementation decision.
