# Phase 5 staging evidence register

## Purpose

Use this register to distinguish implementation and automated test coverage from evidence obtained against real staging or production services. Do not mark a check complete because a feature exists, a mocked test passes, a container builds, or a health endpoint responds.

**Current review baseline:** 2026-11-09  
**Repository baseline:** `main` at `e3ebd66ed52cbc43afca0376b47208f91e9fba26` (2026-11-09). Refresh this SHA after subsequent merges.  
**Live environment evidence supplied for this register:** none. All live validation items below remain pending or blocked until an operator records evidence.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| Implemented | Code or operational procedure exists in the repository. |
| CI-tested | Automated tests/builds passed in GitHub Actions; live service behavior is not implied. |
| Staging-validated | The check was performed against the named staging environment and sanitized evidence was recorded. |
| Production-validated | The check was performed against the intended production deployment with approval and evidence. |
| Blocked | A prerequisite or safety control is missing; do not enable the dependent capability. |
| Not configured | The integration/service is intentionally absent or has no endpoint/credentials configured. |
| Pending | No adequate evidence has been recorded yet. |

## Evidence recording rules

For every live test, record:
- environment identifier (avoid publishing private hostnames or IPs);
- UTC timestamp and operator;
- software/service version where available;
- test identity or bounded test case (never credentials);
- expected and observed result, including counts and truncation;
- sanitized log/report path or restricted evidence reference;
- pass/fail and follow-up issue/action.

Never store API keys, passwords, bearer tokens, authorization headers, private keys, raw sensitive event payloads or unredacted provider responses in this file or public PR comments. Keep detailed artifacts in access-controlled storage and redact internal infrastructure identifiers before sharing.

A diagnostic `passed` result means only that the bounded request/heartbeat passed at that moment. A `skipped`, `not_probed`, missing report or unavailable environment is not a pass.

## Latest repository-side baseline

- PRs #65 and #67 merged the committed frontend lockfile, deterministic `npm ci` in both frontend Dockerfiles, and lockfile-backed dependency auditing in CI.
- PR #66's operational smoke-test and end-to-end contract changes reached `main` through PR #67.
- PR #39's operational-diagnostics regression tests are merged (commit `f7777f7`).
- The frontend build and tests passing in CI are not staging evidence. Docker image builds validate image construction, not live deployment, TLS, persistent storage or integration reachability.
- The live evidence supplied for this register remains **none** until the operator records sanitized staging results below.

## Validation matrix

| Workstream | Repository implementation / CI evidence | Required live evidence | Current status |
| --- | --- | --- | --- |
| Wazuh Manager agent inventory | Read-only paginated Manager adapter, manual sync and mocked API contract tests | Sync registered lab agents including one with no alert; compare agent ID, OS, IP, status and last keep-alive; verify analyst-managed asset fields remain unchanged | Pending |
| Wazuh Indexer alerts | Read-only alert collection, source identity/deduplication and adapter tests | Ingest bounded known lab authentication events; verify source IDs, timestamps, deduplication, finding counts and analyst triage preservation | Pending |
| Wazuh Vulnerability Detector | Read-only `wazuh-states-vulnerabilities*` ingestion and mocked contract tests | Sync known CVE/package records; verify exact agent mapping, package provenance, truncation reporting and remediation-state preservation | Pending |
| CrowdSec LAPI | Separate bouncer-key active-decision reads and optional machine-JWT alert-history reads; bounded evidence, separate source namespaces, exact unique-IP mapping and mocked contract tests | Use an authorized short-lived test decision and alert; collect each twice; verify deduplication, audit events, bounded event evidence, exact asset mapping and no decision/alert mutation. If alert history is enabled, review and approve the broader machine-credential permission risk first | Pending |
| Nuclei isolated worker | Dedicated non-root worker, pinned Nuclei/templates, Redis lease and worker health checks | Before any scan: prove host/cloud DNS/IP egress restrictions, metadata/private-range blocking, DNS-rebinding defenses, exact target allowlist and written authorization; then run only a bounded disposable staging target and test lease-loss/restart | **Blocked — external egress enforcement and written staging authorization not evidenced** |
| Shannon bridge | External bridge adapter, health check and proof-gated finding ingestion; bridge has separate deployment boundary | Deploy on disposable VM; independently verify VM isolation, DNS/IP allowlists, provider budgets, source mount restrictions and written authorization; health check then one authorized disposable target assessment | Blocked pending external runner and isolation evidence |
| Redis detection scheduler | Durable runs, retries, lease fencing, startup recovery and heartbeat tests | On staging Redis: enable controlled schedule, verify run lifecycle, induce worker restart/temporary Redis interruption, confirm recovery/no stale-owner completion/no duplicate incident | Pending |
| Nuclei worker recovery | Durable queued scan jobs, renewable lease, process termination on lease loss and recovery logic | On staging only after egress controls: interrupt worker during a bounded authorized scan; verify lease expiry, process termination, requeue and deduplicated result ingestion | Blocked with Nuclei enablement |
| End-to-end detection | Ingestion, deterministic correlation, incident creation/lifecycle and in-app notifications implemented; CI covers component contracts | Send known authorized lab events; trace source event → finding → correlated detection → incident → per-user notification; record IDs/timestamps and verify repeat evaluation is idempotent | Pending |
| Authentication / RBAC / secrets / API perimeter | JWT validation, Redis login throttling, DB-backed roles, audit events, Host allowlist and security workflow | Review deployed config, TLS/reverse proxy, trusted headers, account/role matrix, rate limits, secret source/rotation, browser exposure and audit redaction; verify no secret leakage | Pending |
| Docker deployment / migrations / storage | Production Compose validation and container builds; Alembic preflight; persistent volumes defined | Deploy in staging from clean state; apply migrations; verify service health, persistent data across restart, permissions, reverse proxy/TLS and rollback procedure | Pending |
| PostgreSQL backup and restore | PowerShell backup, manifest/hash verification and isolated no-network restore drill scripts; syntax check in CI | Execute real backup, verify archive/hash, restore isolated copy, validate Alembic revision/table counts and application-level read-only smoke test; retain sanitized evidence | Pending |
| Off-host retention / RPO / RTO | Runbook documents that encryption, off-host transfer and retention are external operator responsibilities | Configure encrypted off-host copy and retention; perform recovery timing exercise; record measured RPO/RTO and Redis recovery/backup decision | Pending |
| Frontend dependency audit | PR #64 introduced enforced npm audit; Phase 5 PR 1 commits `frontend/package-lock.json`, uses `npm ci` in CI and both frontend Dockerfiles, and audits the committed lockfile | Confirm the final PR 1 head passes frontend tests/build, npm audit and production image build | CI-tested — PR #65 all CI and security jobs passed on head `e282a8f7fe33546b005d02ee51b1f23151b7b7f4` |
| Production Compose smoke test | Phase 5 PR 2 adds an ephemeral Compose startup check with temporary CI-only credentials and disposable volumes | Run deployment/readiness and persistence checks in the intended staging environment | Pending final CI and live staging |
| End-to-end API contract | Phase 5 PR 2 adds a deterministic Wazuh-ingestion → correlation → incident → notification idempotency test | Repeat the flow with authorized lab Wazuh events and record event, finding, detection, incident and notification IDs | Pending live staging evidence |
| Operational diagnostic decision logic | PR #39 covers parsing, status aggregation, heartbeat behavior, Nuclei fail-closed flags and exception redaction; Phase 5 PR 2 adds strict incomplete-check exit behavior | Local helper tests only; real service checks remain in the live-validation rows above | Pending final CI |
## Additional automated coverage planned in Phase 5 PR 2

- A deterministic API-level test will collect three synthetic Wazuh authentication findings, evaluate correlation, verify one linked incident and analyst notification, mark the notification read, and re-evaluate to prove idempotency.
- The production-container CI job will start the built Compose stack with temporary CI-only credentials, wait for PostgreSQL, Redis, API, detection worker and frontend health, verify the migration exit code, and call API readiness through Nginx. CI volumes are removed after the test.
- The diagnostic CLI gains a strict mode that returns a non-zero status when a configured integration remains unprobed. These tests do not change the live-validation statuses in the matrix.

## Safe operator sequence

1. Run the read-only diagnostic from the deployment host/network:
   ```powershell
   python backend/scripts/validate_integrations.py --env-file .env --output artifacts/integration-diagnostics.json
   ```
2. Review the sanitized report locally. Do not publish internal endpoints or secrets. Record each service as passed, failed, skipped or not-probed.
3. For services with passing health checks, perform separately authorized bounded ingestion tests using disposable lab identities/events. Health checks alone do not validate ingestion.
4. Validate scheduler and worker recovery on staging using planned restart/failure drills. Do not simulate failures on production without an approved change window.
5. Keep Nuclei disabled until the external egress policy and written authorization are independently verified. Keep Shannon disabled until its separate VM/bridge controls are verified.
6. Run PostgreSQL backup/restore and off-host retention tests using the dedicated runbook and approved storage.
7. Update this matrix only when sanitized evidence exists. Link restricted evidence by reference; do not commit sensitive artifacts.

## Exit criteria

Phase 5 is not complete until:
- required live integrations have passed bounded staging validation;
- real-event ingestion-to-correlation-to-incident-to-notification has been demonstrated;
- Redis scheduler and worker restart/recovery drills have passed;
- Nuclei and Shannon safety boundaries are independently verified or those engines are explicitly declared disabled/out of scope;
- staging deployment, migrations, persistent storage and security review are documented;
- PostgreSQL restore and off-host recovery objectives have been demonstrated;
- all remaining blocked/not-configured items are explicitly accepted by the project owner.

A green CI run is necessary evidence for code quality, not a substitute for these exit criteria.


## PR #39 — operational diagnostic regression tests

The proposed tests exercise only deterministic local helper behavior. They do not load a deployment environment, instantiate service adapters, contact Wazuh/CrowdSec/Shannon, access Redis/PostgreSQL, launch scans or write operational evidence. A passing CI run must not change any live-validation status in the matrix.
