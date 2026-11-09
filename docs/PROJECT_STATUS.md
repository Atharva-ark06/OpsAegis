# OpsAegis — Project Status

## Implemented and merged
- FastAPI, PostgreSQL, Alembic, Redis, JWT/RBAC and audit logging.
- Authenticated React/TypeScript workspace.
- Wazuh Indexer read-only alert ingestion.
- CrowdSec Local API read-only active-decision ingestion.
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

## Remaining
- Independently validate the Nuclei worker in an authorized staging environment with enforceable egress controls, pinned templates and restart/lease-loss tests.
- Validate Redis scheduler and both worker recovery paths under restart/failure conditions in authorized staging; automated fencing tests do not replace a live Redis failover/restart drill.
- Deploy and independently validate the Shannon bridge on a dedicated disposable VM. The bridge is a controlled single-job reference implementation; job state is in memory, and durable queueing, cancellation, retries, artifact download and full report parsing remain outstanding. No live scan is claimed.
- CrowdSec historical-alert ingestion, full pagination and safe asset association remain outstanding; broad response actions are not implemented.
- Production secrets management, monitoring and operational runbooks.

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
- Alert-observed inventory only: no claim of Wazuh Manager online status, OS inventory or silent-agent discovery. CrowdSec IP-only records are not auto-mapped.


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
- The diagnostic never launches a scan or writes application data. Nuclei remains disabled and is reported as unsafe if its legacy API-process execution flag is enabled.
- A passing check validates only the checked endpoint at that moment; it does not prove telemetry ingestion, worker reliability or production readiness.

### Remaining validation
- Run the diagnostic from the actual deployment network with operator-provided credentials and review the sanitized report.
- Validate Wazuh alert and vulnerability ingestion, Manager inventory sync, CrowdSec decisions and threat-intelligence lookups using authorized test data.
- Move Nuclei execution out of the API process into a separately isolated scanner worker with enforceable egress restrictions before enabling scans.
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


## Operational diagnostics for datastore and worker health (PR #36 — proposed)
- Extends the read-only operator diagnostic to check database SELECT 1 and Redis PING before external integrations.
- Reports the detection-worker Redis heartbeat as required in production; development environments may explicitly report a missing worker as skipped.
- Checks the isolated Nuclei-worker heartbeat only when both NUCLEI_ENABLED and NUCLEI_WORKER_ENABLED are enabled; mismatched flags or a missing heartbeat fail closed.
- Corrects the Nuclei diagnostic guidance to reflect the dedicated worker architecture. The diagnostic never launches a scan or changes configuration/data.
- Adds unit coverage for worker heartbeat states, environment-specific detection-worker expectations and sanitized Redis failures.
- These checks are point-in-time operational signals only. They do not prove worker restart recovery, scanner egress restrictions, live event ingestion or production readiness.
