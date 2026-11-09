# OpsAegis Phase 6 — SOC Automation & Response Orchestration

**Status:** Implementation in progress — Phase 6.1 foundations and a first Phase 6.2 investigation workflow are under review in PR #72  
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

**First bounded increment:** a code-defined, versioned incident-investigation playbook catalogue with strict typed inputs, role-gated preconditions, bounded read-only context lookup and audited dry-run previews. It has no action adapters and cannot execute external actions. This is a foundation only; approval workflows and execution remain future work.

- [x] Versioned playbook definition and strict input validation.
- [x] Operator-only dry-run preview with bounded lookback and audit record.
- [ ] Approval workflow and separation of requester/approver.
- [ ] Allowlisted action adapters, idempotency, timeout and rollback/compensation contracts.
- No automatic containment or blocking by default.

### Phase 6.4 — Reporting and operational metrics
- Collection freshness, source coverage and failure rates.
- Detection-to-incident and incident-to-resolution timing.
- Exportable, privacy-minimized reports with explicit data windows and caveats.

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
