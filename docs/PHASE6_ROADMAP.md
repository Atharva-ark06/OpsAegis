# OpsAegis Phase 6 — SOC Automation & Response Orchestration

**Status:** Phase 6.1–6.3 foundations are merged; Phase 6.4 operational reporting is implemented pending operator-led staging validation.  
**Predecessor:** Phase 5 — Production readiness and end-to-end validation  
**Release posture:** Human-approved automation; no autonomous destructive response.

## Mission

Move OpsAegis from a security-operations visibility and detection platform toward a controlled SOC workflow platform. Phase 6 should reduce repetitive analyst work while preserving provenance, approval, least privilege, auditability and safe failure behavior.

Phase 6 does not retroactively mark Phase 5 staging or production checks as passed. See [the Phase 5 evidence register](PHASE5_STAGING_EVIDENCE.md).

## Product outcomes

1. **Reliable collection operations**
   - Add configurable schedules for supported Wazuh and CrowdSec read-only collection paths.
   - Persist each collection run, source cursor/window, counts, truncation, duration and sanitized failure code.
   - Make retries idempotent and prevent overlapping runs for the same integration.
   - Keep provider quotas and upstream API limits explicit.

2. **Analyst investigation context**
   - Present one incident timeline from source findings, correlated detections, enrichment results, analyst notes and status transitions.
   - Preserve source provenance and distinguish observed facts, provider-derived context and analyst conclusions.
   - Support evidence export with redaction and access control.

3. **Human-in-the-loop playbooks**
   - Introduce versioned playbook definitions with typed inputs, preconditions, permissions and dry-run output.
   - Require explicit approval for any action that changes an external system.
   - Record requester, approver, target, action parameters (redacted), execution result and idempotency key.
   - Default all response integrations to disabled. Never execute arbitrary shell commands or accept arbitrary URLs/targets from a playbook.

4. **Operational reporting**
   - Add time-bounded metrics for collection health, detection volume, incident aging and response workflow outcomes.
   - Show data freshness and incomplete-source warnings; never substitute synthetic data for missing telemetry.

## Delivery increments

### Phase 6.1 — Collection orchestration

Initial implementation scope: Wazuh Manager agent inventory and Wazuh Indexer alert windows only. CrowdSec remains deferred pending a separate least-privilege decision. Schedules are disabled by default; durable run history, a separate Redis-leased worker, bounded retries and manual-run parity are implemented in the current review branch. Automated tests exercise Redis interruption, lease loss, queue deduplication and restart recovery; live staging drills with real Redis and source systems remain required.
- Durable per-integration schedule and run history.
- Per-source enable/disable controls, minimum intervals, bounded lookback and result caps.
- Lease fencing, retry/backoff, overlap prevention and manual run parity.
- Read-only collection only; no response actions in this increment.

### Phase 6.2 — Investigation workspace

Initial implementation scope: incident timeline aggregation, provenance labels, analyst notes and redacted JSON export. Binary attachments, retention enforcement and stronger chain-of-custody controls remain outstanding.
- Unified incident timeline and evidence provenance.
- Analyst notes and evidence attachments with size/type limits, access control and retention rules.
- Redacted export and audit coverage.

### Phase 6.3 — Playbook framework

**Status: bounded framework complete; provider-specific response integration deferred.** The delivered framework includes a code-defined, versioned incident-investigation catalogue, strict typed inputs, role-gated preconditions, bounded read-only context lookup, audited dry-run previews, independent approval records, a durable execution/compensation ledger, read-only operator visibility and fail-closed adapter contracts. No provider adapter is registered or enabled, and no execution endpoint or worker exists.

- [x] Versioned playbook definition and strict input validation.
- [x] Operator-only dry-run preview with bounded lookback and audit record.
- [x] Approval request/decision records with requester/approver separation, expiry and audit trail (no execution).
- [x] Fail-closed adapter interface and metadata contract: fixed action IDs/targets, independent approval requirement, deterministic SHA-256 idempotency key, 1–30 second timeout bound, and explicit compensation action contract.
- [x] Read-only action catalogue endpoint exposes disabled state and reports that execution is unavailable when no provider adapter is registered.
- [x] Draft integration-specific Wazuh agent-isolation threat model: [review document](PHASE6_WAZUH_ISOLATION_THREAT_MODEL.md). Draft only; not security-approved and does not authorize adapter implementation.
- [x] Add a durable execution/compensation ledger schema and fail-closed state-transition guards: [ledger foundation](PHASE6_PLAYBOOK_EXECUTION_LEDGER.md). No dispatch endpoint, worker or provider adapter is added.
- [x] Add a bounded admin/analyst read-only execution-ledger API with status/approval filters and a minimized response: [read API](PHASE6_EXECUTION_LEDGER_API.md). No mutation or dispatch operation is exposed.
- [x] Surface execution and compensation lifecycle states in an admin/analyst-only dashboard panel with status filtering and bounded pagination; the panel remains read-only.
**Deferred integration gate — not part of the completed framework increment:** a concrete Wazuh adapter must remain out of scope until the threat model receives independent security approval, the deployed Wazuh version/API and least-privilege permissions are verified, credentials are provisioned through the operator's secret manager, and written authorization plus disposable staging isolation/unisolation/rollback evidence is reviewed. These are prerequisites for a separate adapter proposal, not evidence that the framework itself is incomplete.

**Recovery/staging increment (combined PR #86):** Adds conservative recovery guidance to the read-only execution ledger, dashboard visibility for unknown/failed compensation states, and an operator-led disposable-staging runbook with an evidence register. This is not a Wazuh adapter or a staging validation result. No live Wazuh request is performed; isolation and unisolation remain disabled and unregistered. See [recovery and staging runbook](PHASE6_RECOVERY_STAGING.md).

- No automatic containment or blocking by default.

### Phase 6.4 — Reporting and operational metrics

**Delivered increments:** authenticated UTC-windowed operational summary and JSON/CSV aggregate export, computed from persisted collection, detection, incident and audit records. Includes source freshness/coverage, collection failure rates and detection/incident lifecycle timing. Reports are privacy-minimized and disclose data limitations; no synthetic metrics are generated.

- [x] Collection freshness, source coverage and terminal failure rates for the two supported collection sources.
- [x] Detection-to-incident timing from linked correlated detections and incident records.
- [x] Incident-to-resolution timing from audited transitions to resolved/closed.
- [x] JSON and CSV aggregate exports with explicit UTC windows and data-quality caveats.
- [x] Daily/weekly trend buckets for persisted collection runs, detections, incidents and audited resolutions.
- [x] Dashboard trend visualizations with explicit empty states and row-cap warnings.
- [x] Administrator-managed, audited thresholds for collection failure rate, source freshness, detection-to-incident time and incident resolution time; read-only threshold breach evaluation.
- [x] Add CI structural validation and an operator-only strict exit gate for the Phase 6.4 evidence register. This validates register completeness only; it is not staging evidence.
- [ ] Run the operator-led staging validation procedure against known source records and measured event timelines; record reviewed sanitized evidence.


**Staging evidence tooling (PR #87):** Adds an offline evidence-register validator. CI checks the template structure only; an operator-only `--require-exit` gate requires complete UTC/version/metric evidence, no row cap, all acceptance items checked and an independent PASS. Neither mode contacts staging or changes the live-validation status. The Phase 6.4 staging item remains pending until reviewed real-environment evidence is recorded.

## Security and reliability invariants

- Least-privilege service credentials; secrets stay backend-side and are never included in logs or evidence exports.
- No unapproved response action. A second authorized approver is required for high-impact actions.
- All external destinations are fixed/allowlisted per integration; no SSRF-capable arbitrary URL input.
- Every scheduled job is bounded, observable, idempotent and protected by a renewable lease/fencing token.
- Retries must not duplicate findings, incidents, notifications or external actions.
- Failed or unavailable enrichment is represented as unknown/unavailable, never as clean.
- Preserve analyst-selected state and existing asset associations during source refresh.
- Scanner safety boundaries from Phase 5 remain in force; Phase 6 does not enable Nuclei or Shannon.

## Phase 6.1 acceptance criteria

- Admins can configure and pause schedules for explicitly supported read-only integrations.
- Each run has a durable record with start/end time, source, status, received/created/updated/skipped counts, truncation indicator and sanitized error code.
- Worker restart, Redis interruption, lease loss and duplicate delivery are covered by automated tests and a staging drill.
- Manual and scheduled collection use the same service path and produce equivalent audit records.
- Rate limits, timeouts, maximum results and schedule minimums are enforced server-side.
- No scanner or response-action endpoint is invoked by collection orchestration.

## Explicit non-goals

- Autonomous blocking, firewall changes, endpoint isolation or account disabling.
- AI-generated severity or remediation claims without traceable evidence.
- Unbounded ingestion or unbounded historical backfill.
- Treating a healthy integration endpoint as proof of complete ingestion.
- Enabling optional integrations merely because code exists.

## Phase 6 planning decisions

Before implementing 6.1, settle:
- which integrations are in the first scheduled-collection allowlist;
- minimum polling intervals and retention for run metadata;
- whether schedules are global or per-tenant (the current application is not documented as multi-tenant);
- operator-visible pause/kill-switch behavior;
- database and Redis recovery expectations.

The first implementation should begin with Wazuh Manager inventory and Wazuh Indexer alerts, then add CrowdSec decisions and optional alert history only after the dedicated machine-credential risk is accepted.
