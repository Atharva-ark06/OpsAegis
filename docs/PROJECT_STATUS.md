# OpsAegis — Project Status

## Phase 5 closeout checkpoint (2026-11-09)

PR #70 is merged at `61c78e66c2980b9ea435a461060d2e8483ea7b69`. It adds optional, bounded CrowdSec alert-history reads using a dedicated machine account, separate from the bouncer-key active-decision path. The feature remains opt-in because CrowdSec machine credentials have broader LAPI permissions.

The repository implementation and automated CI foundations for Phase 5 are in place: deterministic frontend dependency installation/auditing, Wazuh ingestion-to-detection-to-incident-to-notification contract coverage, strict read-only diagnostics, production Compose smoke testing, operational diagnostic regression tests, CrowdSec decision/alert collection contracts, and PostgreSQL backup/restore procedures.

**Phase 5 is not operationally closed.** No sanitized live staging evidence has been supplied for real Wazuh/CrowdSec ingestion, Redis/worker recovery, Nuclei egress enforcement, Shannon VM isolation, TLS/host security, backup restore, off-host retention or measured RPO/RTO. Keep Nuclei and Shannon disabled until their independent safety gates pass. The evidence register and `ops/validate-phase5-evidence.py` distinguish repository/CI checks from actual staging evidence.


## Implemented and merged
- FastAPI, PostgreSQL, Alembic, Redis, JWT/RBAC and audit logging.
- Authenticated React/TypeScript workspace.
- Wazuh Indexer read-only alert ingestion.
- CrowdSec Local API active-decision ingestion with a bouncer key, plus optional bounded alert-history reads using dedicated machine credentials.
- Nuclei authorized-target registry, fixed safe-profile CLI execution, scan history and JSONL finding normalization.
- Shannon external isolated-runner control-plane adapter, authorized target registry, scan dispatch/history, proof-gated finding ingestion and audit logging.
- Separate Shannon bridge reference implementation with exact allowlists, pinned CLI, authenticated API, fail-closed SARIF proof gate and disabled-by-default execution.

## Authentication security hardening (PR #27 — merged)
- Login attempts use shared Redis fixed-window counters by source IP and normalized account; raw identifiers are HMAC-digested for Redis keys.
- Redis failure blocks login rather than silently disabling abuse controls; rate-limit responses include Retry-After.
- Access tokens require issuer, audience, type, token ID, subject, issued-at and expiry claims; roles are resolved from the active database user.
- Failed logins use a dummy password-hash verification for unknown accounts and create privacy-minimized audit events.
- This does not add refresh tokens or server-side token revocation; access tokens remain valid until expiry unless the signing key is rotated or the user is disabled.

## Nuclei boundaries
- Admin-only target registration with a required authorization reference.
- Exact HTTPS URLs only; reject credentials, query/fragment, localhost, metadata, loopback, link-local, multicast and reserved IP targets.
- Only enabled registered targets can be scanned. No arbitrary CLI flags, template paths or user-supplied scan targets.
- Fixed profile disables Interactsh/update checks, bounds rate, concurrency, runtime and output, and excludes DoS/fuzz/intrusive/headless templates.
- Findings deduplicate by template ID + matched URL + matcher name and preserve analyst triage.
- Disabled by default; the dedicated worker image pins Nuclei v3.4.10 and nuclei-templates v10.3.1. Enable both NUCLEI_ENABLED and NUCLEI_WORKER_ENABLED only after staging authorization and network controls are verified.
- Execution is isolated in the dedicated non-root Nuclei worker container (PR #32). The worker is opt-in, uses resource limits and a renewable Redis lease; external DNS/IP egress enforcement remains an operator responsibility.

## Incident response workflow (PR #10)
- Finding status updates are available to admins and analysts and create audit records.
- Incident lifecycle is constrained to open, investigating, contained, resolved and closed states.
- Incidents support active admin/analyst assignment, required resolution notes for resolved/closed states, timestamps and audit records.
- Viewers remain read-only; dashboard controls are role-gated.

## Security correlation engine (PR #11)
- Deterministic rules correlate persisted findings only: repeated Wazuh authentication alerts per identified agent, matching Wazuh agent IP plus CrowdSec active IP/range decision, and target-origin overlap between Nuclei and proof-validated Shannon findings.
- Bounded evaluation window and authentication threshold; false-positive findings are excluded.
- Correlated detections retain source finding IDs, evidence, stable fingerprints and incident linkage. Re-evaluation refreshes the existing detection instead of creating duplicate incidents.
- Detection evaluation and automatic incident creation are audited; viewers can read detections/rules but cannot run evaluation.
- No AI/ML inference, raw event stream, scheduled evaluation, editable rule administration or live engine verification is included. Nuclei/Shannon origin overlap is target-level corroboration, not proof of an identical vulnerability.

## Scheduled detection and alert lifecycle (PR #12)
- Dedicated Redis-backed worker schedules evaluations from a persisted administrator-controlled configuration; disabled by default.
- Queue uses a renewable single-worker lease, durable run rows, startup recovery and up to three attempts with exponential backoff.
- Detection lifecycle: new → acknowledged → investigating → resolved, with audited transitions.
- High/critical detections create per-user in-app notifications for active administrators and analysts; notification reads are user-scoped.
- Worker evaluates only already-persisted findings; it does not collect telemetry, execute scans or send email/SMS/external pages.
- Live Redis worker operation and production scheduling have not been independently validated.

## Remaining Phase 5 gates

### Repository-side closeout
- Keep the CrowdSec alert-history collector explicitly bounded. CrowdSec's documented `GET /v1/alerts` exposes `limit` and time filters (`since`/`until`), not an offset/page cursor. Do not claim complete historical pagination; use bounded collection windows and report possible truncation.
- Keep Shannon classified as a reference bridge, not a production runner. Durable job state, cancellation, retry semantics, artifact retrieval and complete report parsing are not implemented; defer enabling it or scope a separately reviewed runner project.
- Keep all collection/manual sync behavior and scanner boundaries documented; do not add broad response actions without a separate approval and threat-model review.

### Live staging and production evidence
- Deploy the production Compose stack in an authorized staging environment and verify migrations, service health, reverse proxy/TLS, persistent storage and rollback.
- Validate Wazuh Manager inventory, Wazuh Indexer alerts/vulnerabilities, CrowdSec decisions and (only if approved) alert history using disposable lab data.
- Demonstrate real-event ingestion → finding → detection → incident → per-user notification, including repeat/idempotency behavior.
- Run Redis scheduler, detection worker and Nuclei worker recovery drills. Nuclei remains blocked until external DNS/IP egress enforcement and written target authorization are independently verified.
- Validate Shannon only on a dedicated disposable VM after independent isolation, egress, budget and authorization checks; otherwise obtain explicit project-owner acceptance to keep it disabled/out of scope.
- Execute PostgreSQL backup verification and isolated restore; configure encrypted off-host retention; measure RPO/RTO and document the Redis recovery strategy.
- Record operator, UTC timestamp, version, expected/observed counts, sanitized evidence reference, outcome and follow-up for each evidence-register row.

The repository-side validator checks evidence-register structure in CI. Run `python ops/validate-phase5-evidence.py --require-exit` only after staging evidence is recorded and every disabled/out-of-scope item has been explicitly accepted. A green CI run does not close Phase 5.

## Phase 6 implementation (PR #72 merged)

- Adds disabled-by-default schedules for Wazuh Manager registered-agent inventory and Wazuh Indexer alert windows, durable collection run history, a dedicated Redis-leased worker, bounded retries, restart recovery and run fencing. Manual runs use the same Wazuh sync functions as scheduled runs. CrowdSec, scanners and response actions are not part of this worker.
- Adds an incident investigation timeline combining audit changes, analyst notes, correlated detections and linked findings with provenance labels, plus a redacted JSON export. Binary attachments, retention enforcement and stronger chain-of-custody controls remain future work.
- Automated tests were added for schedule enqueue/recovery, role/allowlist enforcement, analyst notes and redaction. They have not been run in this environment; CI must validate the branch. No live integration or staging result is claimed.

## Phase 6 kickoff

Phase 6 begins with the [SOC Automation & Response Orchestration roadmap](PHASE6_ROADMAP.md). Its first increment is durable, bounded, read-only integration collection scheduling. Human approval, auditability and fail-closed behavior remain mandatory; autonomous destructive response is explicitly out of scope.

No live Nuclei scan or engine connection is claimed. Live validation requires explicit written authorization.

See docs/SHANNON_RUNNER.md for runner requirements and limitations. Shannon remains disabled until the external HTTPS runner is configured and health-checked.


The Shannon bridge is not production-ready. Do not enable it until independent egress enforcement, DNS-rebinding defenses, VM isolation, provider budget limits and written staging authorization have been verified.


## Threat intelligence / IOC enrichment (PR #13)
- Read-only, on-demand VirusTotal and AbuseIPDB adapters with server-side credentials, TLS verification, fixed provider origins, no redirects, disabled environment proxy inheritance and bounded timeouts.
- Supported indicators: public IP, domain, HTTP(S) URL and MD5/SHA-1/SHA-256/SHA-512 file hash. Private/reserved addresses, local domains and malformed indicators are rejected.
- AbuseIPDB is IP-only; it explicitly reports not-applicable for other IOC types.
- Provider responses are reduced to normalized verdicts, source-derived scores and selected metadata; raw provider payloads and secrets are not returned.
- IOC records are deduplicated by type/value hash, cached for a configurable TTL, force-refreshable by operators and audit logged.
- Provider errors, rate limits, missing records and missing configuration remain distinct; unavailable provider data is never presented as clean.
- Lookups do not submit URLs/files for scanning, fetch the indicator itself, block traffic or execute response actions.
- Live provider calls require operator-supplied API keys; no keys or live lookup validation are included.


## Asset and endpoint identity (PR #14)
- Wazuh findings with an identified agent ID create or update one source-scoped endpoint asset.
- New findings link to the corresponding endpoint; existing analyst-selected asset assignments are preserved.
- Asset API exposes source engine, external ID, observed IP, agent observation state and last-seen time.
- Source refresh does not overwrite analyst-managed asset type or environment.
- Alert-observed inventory only: no claim of Wazuh Manager online status, OS inventory or silent-agent discovery. CrowdSec IP decisions/alerts map only on one exact, unique existing asset IP; ranges, unknown IPs and ambiguous matches remain unassigned.


## Vulnerability management and CVE intelligence (PR #16)
- Nuclei target registration supports optional explicit association to an existing OpsAegis asset. Scan findings inherit that association only when they do not already have an analyst-selected asset.
- CVE records are created only from CVE identifiers present in Nuclei template IDs, tags or structured classification evidence. No CVE is inferred from a generic title, IOC reputation or guessed score.
- Vulnerability cases retain finding provenance, optional asset, CVE ID, first/last seen, analyst remediation status and notes.
- On-demand NVD CVE API 2.0 lookup stores description, CVSS version/score/severity and NVD publication/modification timestamps; results are cached for 24 hours. Optional NVD API key remains backend-only.
- No NVD bulk sync, Wazuh Vulnerability Detector ingestion, CPE/package matching, automatic remediation or production deployment validation is included.


## Wazuh Manager inventory synchronization (PR #17)
- Separate read-only Wazuh Manager REST API adapter authenticates with backend-only Basic credentials, obtains a short-lived JWT and reads paginated `GET /agents` inventory.
- Agent ID/name/IP/OS/Manager-reported status/lastKeepAlive update Wazuh endpoint assets; registered agents can appear without alert activity.
- Existing asset type/environment are preserved; assets missing from a response are not deleted or marked offline.
- Manager special ID `000` is excluded. API health and manual sync are separate from Indexer alert collection.
- HTTPS/TLS verification mandatory; optional private CA. No enrollment, restart, active response or firewall operation.
- No scheduled sync or live Manager instance validation claimed.


## Wazuh Vulnerability Detector ingestion (PR #18)
- Read-only Indexer query of the documented `wazuh-states-vulnerabilities*` state index, separate from Wazuh alert indices and Manager agent inventory.
- Ingests only CVE-enumerated documents with valid CVE, agent ID, package name and version; retains package metadata, host OS, Wazuh severity/score, timestamps and source document provenance.
- Maps findings to existing endpoint assets by exact Wazuh agent ID; unknown agents remain unmapped, never guessed by IP/name.
- Creates source-specific findings and vulnerability cases; stable Indexer document IDs are hashed for idempotent deduplication.
- Refresh preserves analyst finding triage, vulnerability remediation status/notes, NVD cache metadata and analyst-selected asset assignments.
- Manual admin/analyst sync only, bounded to at most 500 documents per call; partial/truncated results are reported. No scheduled sync, scan trigger, package remediation or live Indexer validation is claimed.


## Production readiness hardening (PR #19 — merged)
- Production startup rejects the development JWT signing key, short/known placeholder secrets and weak database passwords.
- Production requires PostgreSQL, a non-loopback Redis service URL and explicit HTTPS CORS origins (no wildcard, loopback or path-bearing origins).
- Nuclei is blocked in production unless the dedicated isolated scanner worker is enabled with the required external egress policy; it remains disabled by default.
- Added automated configuration tests for accepted production settings and unsafe configuration rejection.
- These checks are configuration guardrails only. They do not prove TLS termination, network isolation, secret-manager integration, backup/restore, live Wazuh/CrowdSec/NVD connectivity, or production deployment.


## Production container deployment foundation (PR #20 — merged)
- Added a separate production Compose stack; the existing development Compose workflow is retained.
- Added non-root production API and detection-worker image, and a multi-stage frontend build served by unprivileged Nginx.
- Added private data network for PostgreSQL and password-protected Redis; database/cache ports are not published to the host.
- Added a one-shot Alembic migration service and startup dependency ordering so API/worker start only after migrations succeed.
- Added API readiness-based health checks, frontend health check, persistent data volumes and container resource limits.
- Added a production environment template with placeholders only and a deployment runbook.
- CI validates Compose configuration and builds the production images. This does not prove a live deployment, TLS termination, backup/restore, monitoring, host hardening or real engine connectivity.


## Responsive SOC frontend foundation (PR #21 — merged)
- Added Tailwind CSS 3 and PostCSS as a utility styling foundation without enabling Preflight, preserving the existing design system.
- Improved responsive navigation, header, overview cards and integration panels; retained light and dark theme support.
- This was an incremental responsive/accessibility foundation, not a complete frontend redesign.

## Live finding severity distribution (PR #22 — merged)
- Overview severity bars are calculated from findings returned by the authenticated API.
- Empty data is represented as an empty state; no synthetic counts are inserted.
- Counts reflect the returned API page (up to 200 findings), not a database-wide aggregate.

## Endpoint inventory filtering (PR #23 — merged)
- Added endpoint inventory summary and client-side filters for reported agent status, environment and source.
- Unknown status values are not counted as online or offline.
- Summary and filters operate on the currently returned API records (up to 200 assets).

## Incident investigation workspace (PR #24 — merged)
- Added expandable incident investigation details, response metadata, linked detections and source finding evidence.
- Linked records are resolved against currently returned API pages; unavailable records are explicitly identified rather than fabricated.
- Full audit event timelines are not exposed by the current incident API and are not represented as if available.

## Engine health visibility (PR #25 — merged)
- SOC engine cards retrieve Nuclei and Shannon health from their authenticated backend health endpoints rather than hard-coding both engines as not configured.
- Health states distinguish healthy, unhealthy, not configured, execution disabled, request unavailable and role-restricted states.
- Only administrator and analyst roles request these health endpoints; viewer cards do not attempt requests that the API would reject.
- Global dashboard refresh rechecks engine health. Health state is not equivalent to a successful scan or proof of live findings ingestion.


## API perimeter hardening (PR #28 — merged)
- Added exact Host-header allowlisting through TrustedHostMiddleware, independent of CORS.
- Production requires explicit lowercase hostnames/IPs; wildcard, scheme and port entries are rejected. The production template includes the public host and loopback for local container health checks.
- Added restrictive API security response headers and no-store caching for authentication routes.
- TLS termination and HSTS remain at the external trusted reverse proxy; forwarded headers are not trusted by this middleware.
- Automated tests cover host allowlisting, response headers and production configuration. No live production deployment is claimed.


## CI preflight guardrails (PR #29 — merged)
- Adds a required first CI job that verifies the shared settings instance can be imported and the FastAPI application starts at import time.
- Applies the complete Alembic migration chain against a disposable SQLite database before downstream CI jobs begin.
- Validates the production Compose file before backend/frontend/runner/container jobs are allowed to run.
- Makes all existing CI jobs depend on preflight, so a configuration or deployment-manifest regression fails early with a focused job/step.
- Adds regression tests for the application settings export and import contract.
- This catches the classes of failures seen in PR #28 before later build/test jobs run; it cannot guarantee error-free changes or validate a live production deployment.


## Phase 5 — Production readiness and end-to-end validation

Phase 5 is in progress. The focus is validating existing integrations and operational boundaries, not adding dashboard features for their own sake.

### Live integration diagnostics (PR #30 — merged)
- Adds an operator-run, read-only diagnostic CLI using the existing Wazuh Manager, Wazuh Indexer, CrowdSec and Shannon adapters.
- Loads local environment values without printing credentials; reports only sanitized check outcomes.
- NVD reachability is opt-in and uses one fixed public CVE lookup. VirusTotal and AbuseIPDB are not queried to avoid unexpected API quota use.
- The diagnostic never launches a scan or writes application data. It checks the dedicated Nuclei worker heartbeat only when both Nuclei enablement flags are set; Nuclei remains disabled by default.
- A passing check validates only the checked endpoint at that moment; it does not prove telemetry ingestion, worker reliability or production readiness.

### Remaining validation
- Run the diagnostic from the actual deployment network with operator-provided credentials and review the sanitized report.
- Validate Wazuh alert and vulnerability ingestion, Manager inventory sync, CrowdSec decisions and threat-intelligence lookups using authorized test data.
- Independently enforce and validate host/cloud DNS/IP egress restrictions for the isolated Nuclei worker before any authorized staging scan.
- Deploy and independently validate the Shannon bridge on a disposable staging VM.
- Complete production secret management, monitoring, backup/restore and operational runbooks.


### Automated secret and dependency scanning (PR #31 — merged)
- Adds a separate GitHub Actions security workflow for pull requests and pushes to `main`.
- Scans the complete Git history with Gitleaks and audits backend and Shannon bridge Python dependencies with `pip-audit --strict`.
- The frontend still has no committed npm lockfile, so the workflow does not claim a locked frontend dependency audit.
- A passing scan does not prove deployed-host security or absence of unknown vulnerabilities.

### Historical secret exposure — remediation status
- The initial full-history scan identified historical VirusTotal and AbuseIPDB key values in an older `.env.example` commit.
- The user confirmed both provider keys were rotated and completed a local full-history rewrite followed by a clean local Gitleaks scan; rewritten branch refs were force-pushed.
- GitHub-side cleanup of unreachable objects, cached content or pull-request refs has not been independently verified.


## Isolated Nuclei worker (PR #32 — merged)
- Scan requests are persisted in PostgreSQL, delivered through Redis and executed by a dedicated non-root worker container; the API no longer starts the Nuclei subprocess.
- The worker has a renewable Redis lease, heartbeat, interrupted-run recovery and bounded retries. Its Compose service is opt-in and has a read-only root filesystem, dropped capabilities, no-new-privileges and CPU/memory/PID limits.
- Nuclei remains disabled by default. Docker Compose networking is not an egress allowlist; host/cloud DNS and IP destination restrictions remain mandatory before staging scans.
- CI/image builds do not prove live scanner behavior, egress isolation or production deployment.

## Nuclei worker lease and template hardening (PR #33 — merged)
- Active scans are terminated when the worker loses its Redis lease; uncommitted results are discarded so a new lease owner can recover the durable running job.
- Worker image pins Nuclei v3.4.10 and nuclei-templates v10.3.1, installs templates at build time and passes the directory explicitly to the scanner. Runtime template downloads/updates are disabled.
- Adds regression tests for lease-loss process termination and explicit template-directory use.
- This does not validate deployment-level egress policy or authorize any live scan.


## Scheduled detection worker fencing and health (PR #34 — merged)
- Persisted a per-run worker fencing token; completion and retry/failure updates are conditional on the current token, so a stale worker cannot finalize a run after a new owner has reclaimed it.
- A worker that detects lease loss leaves its durable run for startup recovery rather than marking it successful. Correlation evaluation is idempotent and may be repeated safely.
- Startup recovery clears stale worker ownership and requeues interrupted runs within the existing attempt budget.
- Production Compose now reports detection-worker and opt-in Nuclei-worker health from Redis heartbeat keys rather than container process state alone.
- Added tests for lease loss before execution, lease loss during evaluation and stale-owner completion rejection.
- This does not constitute a live Redis failover/restart drill or production deployment validation.


## Integration ingestion contract coverage (PR #35 — merged)
- Adds API-level regression coverage for CrowdSec active-decision ingestion, Wazuh Manager inventory refresh and Wazuh Vulnerability Detector refresh.
- Verifies repeat collection is idempotent and audited, analyst triage and first-seen timestamps remain intact, and source refresh does not overwrite analyst-managed asset classification/environment.
- Verifies vulnerability refresh updates source-derived severity while preserving analyst remediation status/notes and NVD cache metadata.
- Adds viewer-role denial tests for the covered sync operations.
- Adds a Phase 5 runbook that separates mocked CI evidence from required live-service, staging, deployment, backup/restore and security validation.
- These tests use mocked adapters and disposable SQLite; they do not claim live Wazuh/CrowdSec/provider connectivity or production readiness.


## Operational diagnostics for datastore and worker health (PR #36 — merged)
- Extends the read-only operator diagnostic to check database SELECT 1 and Redis PING before external integrations.
- Reports the detection-worker Redis heartbeat as required in production; development environments may explicitly report a missing worker as skipped.
- Checks the isolated Nuclei-worker heartbeat only when both NUCLEI_ENABLED and NUCLEI_WORKER_ENABLED are enabled; mismatched flags or a missing heartbeat fail closed.
- Corrects the Nuclei diagnostic guidance to reflect the dedicated worker architecture. The diagnostic never launches a scan or changes configuration/data.
- Adds unit coverage for worker heartbeat states, environment-specific detection-worker expectations and sanitized Redis failures.
- These checks are point-in-time operational signals only. They do not prove worker restart recovery, scanner egress restrictions, live event ingestion or production readiness.


## PostgreSQL backup and isolated restore tooling (PR #37 — merged)
- Adds a PowerShell backup command that runs PostgreSQL custom-format pg_dump inside the production database container without putting the database password in the command line.
- Creates a timestamped archive and a JSON manifest with file size, UTC timestamp and SHA-256; checks archive readability with pg_restore before copying it to the host.
- Adds a separate integrity command that validates the manifest/hash and parses the archive directory using the PostgreSQL container's pg_restore utility.
- Adds an isolated restore drill using a disposable postgres:16-alpine container with no network and no published ports. It restores the archive, checks the Alembic revision and public table count, then removes the container by default.
- Ignores local backup artifacts and the dedicated restore environment file; documents encryption, off-host retention, Redis backup boundaries and recovery evidence.
- Adds a Windows CI job that parses every PowerShell operations script for syntax errors.
- These scripts do not encrypt or upload backups, schedule retention, back up Redis, connect a restored database to the application, or prove disaster-recovery readiness. Operators must perform the drill in their own environment.


## Staging validation evidence register (PR #38 — merged)
- Adds a structured evidence register for Phase 5, separating implemented, CI-tested, staging-validated, production-validated, blocked and not-configured states.
- Records each live validation item with environment, timestamp, operator, sanitized evidence reference, result/counts and follow-up action; no credentials or raw sensitive payloads belong in the register.
- Defines read-only diagnostics as connectivity checks only. Passing health checks do not prove event ingestion, correlation, notification delivery, worker recovery or production readiness.
- Explicitly tracks Wazuh Manager inventory and Indexer alerts/vulnerability ingestion, CrowdSec collection, Nuclei egress controls and authorized staging readiness, Shannon bridge, Redis scheduler/worker recovery, end-to-end detection, authentication/RBAC/secrets, deployment/migrations/storage and PostgreSQL restore/off-host retention/RPO/RTO.
- No live services are contacted by this documentation change. No scan, deployment, backup or restore is performed. All unverified live checks remain pending until an operator records evidence from the intended staging/production environment.


## Operational diagnostics regression coverage (PR #39 — merged; commit `f7777f7`)
- Adds focused unit tests for the operator diagnostic's environment-file parser, result classification, heartbeat behavior, production/development detection-worker expectations and Nuclei fail-closed enablement.
- Verifies disabled Nuclei does not query Redis, mismatched enablement flags fail without probing, and enabled Nuclei requires the dedicated worker heartbeat.
- Verifies diagnostic exception details expose only exception class names, not potentially sensitive exception messages.
- These tests validate local decision logic only. They do not contact external services, prove live integration connectivity, validate egress policy or replace staging recovery drills.


## Phase 6.3 first increment (PR #73 merged)

- Adds a versioned, code-defined incident-investigation playbook catalogue.
- Adds strict typed input validation, admin/analyst-only dry-run previews, bounded read-only context lookup and audit records.
- No external action adapter, command execution, scanner invocation, containment, notification or approval bypass is introduced. Approval and controlled execution remain separate future increments.


## Phase 6.3 second increment (approval workflow foundations)

- Adds durable approval requests tied to a versioned playbook and incident, with bounded inputs and a 24-hour expiry.
- Requires a different active administrator/analyst to approve or reject; requesters cannot approve their own requests.
- Decisions are single-use, expiry-aware and audit-logged.
- Approval is a recorded governance decision only: it does not execute the playbook, invoke external integrations, or enable response actions.


## Phase 6.3 action-adapter safety contracts (PR in review)

- Adds a read-only action catalogue and a fail-closed adapter contract. The initial Wazuh agent-isolation action is descriptive only: no provider adapter is registered, enabled or callable.
- Requires independent human approval, deterministic SHA-256 idempotency keys bound to approval/action/target/parameters, a bounded 1–30 second adapter timeout, and a declared compensation action.
- Adapter interfaces distinguish execution results from compensation results; compensation is not represented as a successful rollback unless a future provider adapter reports it.
- Adds tests for disabled-by-default behavior, missing adapter rejection, timeout bounds, independent-approver requirements, compensation metadata and stable idempotency keys.
- No endpoint isolation, unisolation, external request, command execution or other response action is performed. A concrete provider adapter remains gated on integration-specific threat modelling and authorized staging validation.


## Phase 6.4 — operational reporting (PR in review)

- Adds authenticated `GET /api/v1/reports/operations` with explicit UTC `since`/`until` bounds (default seven days, maximum 90 days).
- Reports collection source coverage, successful/failed run counts, terminal failure rate, received/created/updated/skipped totals, possible truncation and freshness against the last successful run.
- Reports mean detection-to-incident time from linked correlated detections and mean incident-to-resolution time from the first audited transition to resolved/closed.
- Adds aggregate JSON and CSV export. The response excludes incident titles, descriptions, raw detection evidence, user identities, credentials and provider payloads.
- Includes explicit data-quality caveats and bounded metric queries. These are repository-derived operational metrics, not proof of complete upstream telemetry or live staging health.


## Phase 6.4 — operational trends and thresholds (PR pending review)
- Adds authenticated daily/weekly trend buckets for persisted collection runs, correlated detections, incidents and audited resolution transitions, with a 10,000-row bound and explicit data-quality caveats.
- Adds a dashboard operational trends panel with collection success/failure and detection/incident volume visualizations; empty data is shown as empty, never fabricated.
- Adds persisted singleton operational thresholds. Administrators can configure collection terminal-failure percentage, source freshness age, detection-to-incident SLA and incident-resolution SLA; changes are audit logged. Analysts/viewers can read thresholds and computed breach summaries but cannot change settings.
- Threshold breaches are evaluated from the same persisted report metrics over a rolling seven-day window. They do not trigger external notifications or response actions.
- Automated tests cover bucket counts, weekly mode, authentication, role restrictions, validation and threshold audit records. CI must validate this branch; no live staging data is claimed.
