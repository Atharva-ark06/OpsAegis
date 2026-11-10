# OpsAegis

**Operational Security & Incident Governance System**

A unified security operations and threat-response platform integrating Wazuh, CrowdSec, Nuclei and Shannon through an independent orchestration, normalization, correlation and incident-management layer.

## Current implementation

- FastAPI backend, PostgreSQL persistence, Redis service, Alembic migrations and JWT/RBAC.
- Authenticated React/TypeScript operational workspace (PR #5).
- Wazuh Indexer read-only alert ingestion with source-event deduplication.
- CrowdSec Local API active-decision ingestion and optional bounded alert-history collection (PR #6; alert history requires a separate machine credential).
- No fabricated alerts, live metrics or engine connectivity claims.

A built adapter is not proof of a live connection. Configure and verify each authorized engine endpoint before expecting its records.

## Authentication security

Login throttling, strict JWT claim validation and failed-login audit controls are documented in [Authentication Security](docs/AUTHENTICATION_SECURITY.md).

## Security engines

| Engine | Role | Integration status |
|---|---|---|
| Wazuh | Endpoint telemetry and SIEM alerts | Indexer read-only adapter |
| CrowdSec | Behavioural threat decisions and detection alerts | LAPI bouncer decision adapter; optional machine-JWT alert adapter |
| Nuclei | Authorized vulnerability scanning | Authorized target registry and safe-profile scans |
| Shannon | Authorized AI-assisted application testing | External isolated-runner control-plane adapter (runner deployment required) |

## CrowdSec Local API integration

OpsAegis reads active decisions from /v1/decisions using a dedicated bouncer API key in the X-Api-Key header. Bouncer credentials are read-only and cannot access alert history. Optional historical alert ingestion uses a separate dedicated machine ID/password to obtain a short-lived JWT and then calls only GET /v1/alerts. CrowdSec machine credentials have broader LAPI permissions than bouncer keys; keep these optional values blank unless the project owner explicitly accepts that credential risk. The implementation never sends alert/decision create, update or delete requests.

Configure the backend .env:

| Variable | Purpose |
|---|---|
| CROWDSEC_LAPI_URL | HTTPS Local API base URL, e.g. https://crowdsec.internal:8080 |
| CROWDSEC_API_KEY | Dedicated bouncer API key |
| CROWDSEC_CA_CERT | Optional trusted CA certificate path |
| CROWDSEC_MACHINE_ID | Optional dedicated CrowdSec machine login; enables alert-history collection |
| CROWDSEC_MACHINE_PASSWORD | Optional password for that dedicated machine; backend only |
| CROWDSEC_TIMEOUT_SECONDS | Request timeout, 1–60 seconds |
| CROWDSEC_MAX_RESULTS | Maximum decisions or alerts per collection, 1–1000 |

Create a dedicated bouncer key on the CrowdSec host with cscli bouncers add opsaegis-readonly. Store it only in the backend environment. For optional alert history, use a separate dedicated machine account—not the CrowdSec agent's production credentials—and store its login/password only in the backend environment. Machine credentials can authenticate to broader LAPI operations, so this optional integration is disabled unless both values are explicitly configured. OpsAegis exchanges them for a short-lived JWT and issues only GET /v1/alerts; it never calls alert/decision mutation endpoints. Do not expose either credential type to frontend variables.

After configuration, restart the backend. Authenticated admin/analyst endpoints:

- GET /api/v1/integrations/crowdsec/health
- POST /api/v1/integrations/crowdsec/collect
- POST /api/v1/integrations/crowdsec/alerts/collect (optional machine credentials required)

Active-decision collection imports /v1/decisions and retains decision ID, scope, value, action, scenario, origin and duration as bounded evidence. The current decision response does not provide a reliable event timestamp, so ingestion time is used as observation time. Optional alert-history collection uses /v1/watchers/login and GET /v1/alerts with a bounded limit; it records alert metadata and a bounded decision summary but deliberately excludes raw event payloads. Decision and alert findings use separate source namespaces and deduplicate independently. Both collection paths are manual/pull-based; scheduled polling is not yet implemented.

## Wazuh Indexer integration

Configure backend-only WAZUH_INDEXER_URL, WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD, optional WAZUH_INDEXER_CA_CERT, WAZUH_INDEXER_TIMEOUT_SECONDS and WAZUH_INDEXER_MAX_RESULTS. Use a dedicated read-only Indexer account, HTTPS and certificate verification. Endpoints: GET /api/v1/integrations/wazuh/health and POST /api/v1/integrations/wazuh/collect.

## Production configuration guardrails (PR #19)

Set `OPS_AEGIS_ENV=production` before starting the API or detection worker in a production deployment. The application now fails during startup when production settings contain:
- The development JWT secret, a short secret, or a known placeholder.
- SQLite instead of PostgreSQL, or a database URL with a weak/short password.
- A loopback Redis URL.
- Wildcard, HTTP, loopback or path-bearing CORS origins; configure exact HTTPS origins only.
- `NUCLEI_ENABLED=true` and `NUCLEI_WORKER_ENABLED=true` only after the isolated scanner worker and external egress policy have been verified. The worker is opt-in via the Compose `scanner` profile.

Generate a unique application signing key (never commit it):

    python -c "import secrets; print(secrets.token_urlsafe(48))"

Use a unique database password of at least 16 characters and encode reserved URL characters when placing it in `DATABASE_URL`. Keep all values in an untracked deployment environment file or a secrets manager. The checked-in `.env.example` values are development examples, not production credentials.

The existing `docker-compose.yml` is a local development stack, not a production deployment recipe. Production still requires a reviewed deployment topology, TLS termination, secrets management, network policy, backups, monitoring and isolated scanner/runner infrastructure. These configuration checks do not constitute a production deployment or live integration validation.

## PostgreSQL backup and restore

Production operators can create a PostgreSQL custom-format backup, verify its SHA-256/archive directory, and run a full restore drill in a disposable container with no network or published ports. See [the PostgreSQL backup and restore runbook](docs/DATABASE_BACKUP_RESTORE.md). The PowerShell scripts are under `ops/`. Backups are sensitive and are not encrypted by these scripts; use encrypted off-host storage and a separately managed retention policy. Redis backup is outside this workflow.

## Development checks

    cd backend
    pip install -r requirements.txt
    pytest
    cd ../frontend
    npm install
    npm test
    npm run build

## Security principles

- Connect only to infrastructure and targets for which the operator has authorization.
- Keep engine credentials server-side; never expose them to frontend bundles.
- Enforce TLS verification and bounded timeouts/results.
- Preserve upstream source IDs and evidence provenance; deduplicate repeated ingestion.
- Never overwrite analyst triage state during collection.
- Distinguish active CrowdSec decisions from historical alerts and firewall enforcement.
- Nuclei and Shannon workers require target allowlists, explicit authorization, isolation, resource limits and audit trails before execution is enabled.

See docs/PROJECT_STATUS.md and docs/SECURITY_BASELINE.md for implementation boundaries. Phase 5 exit requirements and the evidence-register validator are documented in [the Phase 5 staging evidence register](docs/PHASE5_STAGING_EVIDENCE.md). The next product increment is defined in the [Phase 6 SOC automation roadmap](docs/PHASE6_ROADMAP.md). For Phase 5 live-service and staging validation steps, see [the integration validation runbook](docs/PHASE5_INTEGRATION_VALIDATION.md) and [the staging evidence register](docs/PHASE5_STAGING_EVIDENCE.md).

## Nuclei authorized scanning

Nuclei is disabled by default. The dedicated worker image contains Nuclei v3.4.10 and pinned templates v10.3.1; do not install or run Nuclei in the API container. Keep both NUCLEI_ENABLED and NUCLEI_WORKER_ENABLED false until the worker profile, host/cloud egress policy, DNS-rebinding defenses and written staging authorization have been independently verified. Admins register exact HTTPS targets with an authorization reference; admins and analysts can list targets and scan history and enqueue the fixed safe profile. API endpoints: GET /api/v1/integrations/nuclei/health, GET /targets, POST /targets, POST /targets/{id}/scans and GET /scans under the integrations/nuclei prefix.

The API accepts no arbitrary CLI flags, template paths or free-form scan URLs. The fixed profile disables Interactsh and update checks, bounds rate/concurrency/runtime/output and excludes DoS, fuzzing, intrusive and headless template tags. Findings are deduplicated; analyst triage state is preserved. Only scan systems for which you have written authorization.

Deployment limitation: Nuclei scan requests are queued in PostgreSQL/Redis and executed by the separate non-root `nuclei-worker` image. Start it only with the Compose `scanner` profile. The worker kills an active scan if it loses its Redis lease. The Compose egress network is not an allowlist: apply DNS/IP destination restrictions at the host/cloud firewall before enabling scans. See [the Nuclei worker deployment guide](docs/NUCLEI_WORKER.md). No live scan or deployed egress policy is claimed.


## Shannon authorized application testing

OpsAegis provides an authenticated control-plane adapter for a separately deployed Shannon runner bridge. Shannon OSS is a CLI/worker orchestrator, not a native HTTP API; OpsAegis does not execute Shannon inside FastAPI or expose the Docker socket to the backend.

See [docs/SHANNON_RUNNER.md](docs/SHANNON_RUNNER.md) for the bridge API contract, deployment boundary, security requirements and licensing notes. Shannon OSS is AGPL-3.0; its source is not embedded in this repository.

The integration is disabled by default. Configure backend-only SHANNON_ENABLED, SHANNON_RUNNER_URL and SHANNON_RUNNER_TOKEN only after deploying and reviewing the isolated bridge. Admins register an HTTPS staging target, its GitHub source repository and a written authorization reference. Only admins can dispatch an assessment. Analysts can view and sync scan history.

Findings are accepted only when the bridge reports validation_status=exploited and supplies non-empty proof evidence. Repeated results are deduplicated and analyst triage state is preserved. A configured adapter is not proof of a live Shannon engine: no bridge, model-provider key or live scan is included in this PR.

Shannon actively exploits applications and may mutate state. Use disposable lab/staging environments only; never production. The runner must enforce DNS/IP egress allowlists, isolation, resource budgets, read-only source mounts and prompt-injection safeguards.


## Shannon isolated runner deployment

PR #9 adds a separate reference bridge under [runner/shannon-bridge](runner/shannon-bridge/README.md). It is not part of the OpsAegis backend container or the local Docker Compose stack. Deploy only on a dedicated disposable Linux VM with an independently enforced egress firewall/proxy, exact target and repository allowlists, a pinned Shannon CLI and written staging authorization. The bridge remains disabled by default. See [the runner deployment contract](docs/SHANNON_RUNNER.md).

The bridge is a controlled single-job validation implementation, not an HA production queue. Job state is in memory; cancellation, durable retries, artifact download and a full report parser are not implemented. SARIF ingestion fails closed unless explicit proof metadata and an in-scope affected URL exist. CI does not run Shannon. No live pentest or live engine connection is claimed.


## Incident response and finding triage

Analysts and administrators can update finding triage through `PATCH /api/v1/findings/{id}/status` with one of `new`, `triaged`, `accepted`, `false_positive` or `resolved`. Each actual status change is audit logged. Viewers remain read-only.

Incidents support `PATCH /api/v1/incidents/{id}` for assignment, status and resolution notes. Valid transitions are open → investigating → contained → resolved → closed, with controlled returns from investigating/contained/resolved to earlier active states. Closed incidents are terminal. A non-empty resolution note is required before resolving or closing. Assignees must be active admins or analysts. Changes are audit logged. The dashboard exposes these actions only to admin/analyst users.


## Phase 6.1 — Read-only collection orchestration

The Integrations workspace includes an administrator-controlled scheduler for two allowlisted read-only sources:
- Wazuh Manager registered-agent inventory.
- Wazuh Indexer alert windows.

Schedules are disabled by default. Administrators configure an interval (60–86,400 seconds) and bounded lookback (1–43,199 minutes). Admins and analysts can queue a manual run. Manual and scheduled runs use the same existing Wazuh sync paths; each execution has a durable run record with attempt count, result counts, possible truncation, sanitized error code and timestamps.

A separate `collection-worker` service uses a Redis lease, worker fencing token, bounded retry/backoff and startup recovery. It does not call CrowdSec machine-credential endpoints, Nuclei, Shannon or response-action APIs. Upstream result limits and HTTP timeouts remain enforced by the existing Wazuh adapters. A green worker heartbeat is not proof that a source is configured or that telemetry was collected.

Endpoints:
- `GET /api/v1/collections/schedules`
- `PUT /api/v1/collections/schedules/{source}` (admin)
- `POST /api/v1/collections/{source}/run` (admin/analyst; returns 202)
- `GET /api/v1/collections/runs`

## Phase 6.2 — Incident investigation timeline

The incident investigation view now combines incident audit changes, analyst-authored notes, correlated detections and linked source findings into a bounded, provenance-labelled timeline. Admins and analysts can add notes (1–5,000 characters). Operators can export a JSON evidence package with secret-like keys and common bearer/API-key patterns redacted. Exports are marked `no-store`.

Endpoints:
- `GET /api/v1/incidents/{id}/timeline`
- `POST /api/v1/incidents/{id}/notes` (admin/analyst)
- `GET /api/v1/incidents/{id}/evidence-export` (admin/analyst)

Evidence attachments are now supported through admin/analyst-only upload, list and download endpoints:
- `POST /api/v1/incidents/{id}/attachments` (multipart field `file`)
- `GET /api/v1/incidents/{id}/attachments`
- `GET /api/v1/incidents/{id}/attachments/{attachment_id}`

Uploads are content-sniffed (PDF, PNG, JPEG or UTF-8 text), capped at 10 MiB by default (25 MiB hard configuration ceiling), stored in a persistent volume outside the web root, and never embedded in JSON exports. Downloads verify SHA-256 before serving and force attachment disposition with `no-store` and `nosniff`. Metadata includes uploader, size, digest and expiry; the default retention is 365 days. Configure `EVIDENCE_STORAGE_PATH`, `EVIDENCE_MAX_ATTACHMENT_BYTES` and `EVIDENCE_RETENTION_DAYS` on the backend. Production Compose mounts the `evidence_data` volume and the proxy caps request bodies at 11 MiB.

Expired-file pruning is explicit and dry-run by default:
```powershell
docker compose -f compose.production.yaml exec backend python scripts/purge_expired_evidence.py
docker compose -f compose.production.yaml exec backend python scripts/purge_expired_evidence.py --apply
```
Run the first command to inspect the count; use `--apply` only under an approved retention procedure. Back up the evidence volume with the database, protect it with encrypted off-host storage, and restrict volume access. This implementation does not provide automatic scheduled deletion, malware scanning, tenant isolation, immutable/WORM storage or a cryptographic chain of custody. Phase 6.2 still requires staging validation and an independently reviewed retention/backup drill. See [the evidence attachment runbook](docs/PHASE6_EVIDENCE_ATTACHMENTS.md).

## Scheduled detection, lifecycle and notifications

PR #12 adds a dedicated `detection-worker` service to Docker Compose. It uses a Redis queue, a renewable single-worker lease, persisted scheduled-run records, startup recovery for interrupted work and bounded retries (up to three attempts with exponential backoff). Scheduled evaluation is **disabled by default**.

After applying migrations and starting the Compose stack, an administrator can enable the schedule through the authenticated API:

- `GET /api/v1/detections/scheduler` — configuration, Redis connectivity and worker heartbeat.
- `PUT /api/v1/detections/scheduler` — set `enabled`, `interval_seconds` (60–3600), `window_minutes` (1–1440) and `auth_threshold` (3–20). Enabling schedules the first run after the configured interval.
- `GET /api/v1/detections/runs` — recent execution history and retry state.

Only administrators can change scheduling. Admins and analysts can transition detections through `new → acknowledged → investigating → resolved`; each transition is audited. High/critical detections create per-user in-app notifications for active admins and analysts. Read them through `GET /api/v1/detections/notifications` and mark one read with `PATCH /api/v1/detections/notifications/{id}/read`. Notifications are in-app only; email, SMS and external paging integrations are not included.

The worker does not collect source telemetry or launch scans. It evaluates only persisted findings already ingested by OpsAegis. Keep the scheduler disabled if Redis or the worker is unavailable; the API exposes heartbeat state and queued/failed runs remain visible for diagnosis.


## Threat intelligence and IOC enrichment (PR #13)

OpsAegis supports on-demand, read-only enrichment for public IPv4/IPv6 addresses, domains, HTTP(S) URLs and MD5/SHA-1/SHA-256/SHA-512 hashes.

Optional providers are VirusTotal and AbuseIPDB. Configure credentials only in the backend .env:
- VIRUSTOTAL_API_KEY — VirusTotal API key; supports IP, domain, URL and file-hash lookups.
- ABUSEIPDB_API_KEY — AbuseIPDB API key; supports public IP lookups only.
- THREAT_INTEL_TIMEOUT_SECONDS — provider request timeout (1–30 seconds).
- THREAT_INTEL_CACHE_TTL_SECONDS — repeat lookup cache lifetime (60–86400 seconds; default 15 minutes).

Run the Alembic migration before using the workspace. Authenticated users can view provider configuration and IOC history. Admins/analysts can submit an indicator for enrichment. Provider results are normalized, persisted and audit logged; repeated lookups are cached, with an explicit force-refresh option. Provider API keys never leave the backend.

The integration performs lookup requests only: it does not submit files or URLs for scanning, visit the indicator URL, block traffic or change firewall controls. Private, loopback, link-local, reserved IPs and local/reserved domains are rejected. AbuseIPDB is marked not applicable for non-IP indicators. Provider errors/rate limits are not converted into clean verdicts. The overall risk score is the maximum score reported by successful providers; it is a source-derived indicator, not an OpsAegis probability or guarantee.

No provider key or live provider lookup is included. Without credentials the workspace reports providers as not configured and enrichment returns HTTP 503.


## Asset and endpoint identity (PR #14)

Wazuh alert collection resolves upstream agent identity from alert evidence and upserts one endpoint asset per Wazuh agent ID. New findings link to that asset; existing analyst-selected asset associations are preserved. Repeated collection refreshes the endpoint name, observed IP and last-seen timestamp without overwriting its environment or asset type.

This is alert-observed inventory, not a substitute for the Wazuh Manager agents API. It does not prove current online status, collect OS inventory, or discover agents that have not generated an ingested alert. CrowdSec IP-only records are linked only when one exact existing asset IP match is unambiguous; range and ambiguous matches remain unassigned.


### Frontend appearance
- Dark, light, and system-following themes are available from the authenticated header and sign-in screen.
- Theme preference is stored locally in the browser; no theme preference or browser storage value is sent to the API.
- System mode follows the operating system color-scheme preference. Theme changes apply without a page reload.


## Vulnerability management and CVE intelligence (PR #16)

OpsAegis creates vulnerability cases only when an authorized Nuclei scan returns a CVE identifier in the template ID, tags or structured classification. An administrator may optionally map a registered Nuclei target to an existing OpsAegis asset; findings from that target inherit the explicit mapping only when the finding has no prior asset assignment. Unmapped findings remain unmapped.

The Vulnerabilities workspace provides CVE, CVSS severity, asset and remediation-status filters, finding provenance, analyst notes and remediation states. Admins and analysts can request a read-only lookup of a known CVE from the official NVD CVE API 2.0. CVSS score/version/severity, description and NVD publication/modification timestamps are stored with a 24-hour cache. Configure optional backend-only `NVD_API_KEY` to increase NVD request allowance, and `NVD_TIMEOUT_SECONDS` (1–30, default 10). Never expose the key through frontend variables.

NVD lookup enriches CVE metadata; it does not establish that an asset is affected. Asset association is based solely on explicit target-to-asset mapping and the original scanner finding. A Nuclei template without a CVE identifier does not create a CVE record. This feature does not yet import Wazuh Vulnerability Detector inventory, perform package/CPE matching, auto-remediate, or claim complete endpoint coverage. Apply Alembic migration `0011_vulnerability_management` before using the workspace.

Reference: [NVD Vulnerabilities API 2.0](https://nvd.nist.gov/developers/vulnerabilities).


## Wazuh Manager agent inventory (PR #17)

OpsAegis can connect to the Wazuh Manager REST API for read-only synchronization of registered agents, including agents that have not generated alerts. Configure `WAZUH_MANAGER_URL` (HTTPS), `WAZUH_MANAGER_USERNAME`, `WAZUH_MANAGER_PASSWORD`, and optionally `WAZUH_MANAGER_CA_CERT`. The adapter obtains a short-lived API JWT server-side, reads paginated `GET /agents` records, and stores agent name, ID, IP, OS and Manager-reported connection status in endpoint assets. Use an API account limited to inventory read permissions. TLS verification is mandatory.

Endpoints: `GET /api/v1/integrations/wazuh-manager/health` and `POST /api/v1/integrations/wazuh-manager/sync`. Sync is manual and bounded by `WAZUH_MANAGER_MAX_AGENTS` (1–2000; default 500). Wazuh's special agent ID `000` is excluded. Sync does not delete assets missing from a response, infer offline state from missing data, enroll/restart/disconnect agents, or call active-response APIs. Existing analyst-managed asset type and environment are preserved.

Reference: [Wazuh API authentication](https://documentation.wazuh.com/current/user-manual/api/getting-started.html) and [Wazuh API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html).


## Wazuh Vulnerability Detector inventory (PR #18)

The Wazuh Indexer adapter can read the documented `wazuh-states-vulnerabilities*` index using the existing backend-only Indexer credentials. This is separate from alert collection and Wazuh Manager agent inventory. Configure Wazuh Vulnerability Detection and confirm the state index exists before using the manual sync.

Authenticated admin/analyst endpoint: `POST /api/v1/integrations/wazuh-vulnerabilities/sync`. The Vulnerability Management workspace includes a manual sync control. The query is read-only and bounded to at most 500 results per call (also capped by `WAZUH_INDEXER_MAX_RESULTS`). A truncated response is explicitly reported; repeat syncs are idempotent for stable Indexer document IDs.

Only CVE-enumerated records with a valid CVE ID, agent ID and package name/version are ingested. Package, version, architecture, host OS, Wazuh severity/score, detected/published timestamps and source provenance are retained as finding evidence. Endpoint association uses exact Wazuh agent ID; unmatched endpoints remain unmapped. Repeated sync preserves analyst remediation status/notes and finding triage. No Manager vulnerability endpoint or scan-trigger action is called.


## Production Docker deployment (PR #20)

A separate production Compose stack is available in `compose.production.yaml`; the original `docker-compose.yml` remains the local development stack. The production stack uses non-root API/worker containers, a compiled React frontend served by unprivileged Nginx, password-protected Redis, private PostgreSQL/Redis networking, a one-shot Alembic migration service, persistent volumes, Redis-heartbeat worker health checks and container resource limits. Scheduled detection runs use persisted worker fencing tokens so stale workers cannot finalize work after ownership changes. The browser uses same-origin `/api/v1` requests through the Nginx reverse proxy.

Start with `.env.production.example`, copy it to the untracked `.env.production`, replace every placeholder, and set the same URL-safe database/Redis passwords in their respective service and connection-string variables. Set the exact public HTTPS `CORS_ORIGINS` value and a newly generated `OPS_AEGIS_SECRET_KEY`.

```powershell
Copy-Item .env.production.example .env.production
# Edit .env.production and replace every placeholder before continuing.
docker compose --env-file .env.production -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.production.yaml up -d --build
docker compose --env-file .env.production -f compose.production.yaml ps
```

The frontend is bound to `127.0.0.1:8080`; place a maintained TLS reverse proxy/load balancer in front of it. PostgreSQL, Redis and the API are not published on host ports. Do not expose internal service ports to the public internet. See [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md) for secrets, TLS, worker health/recovery operations and limitations.

This is a production-oriented container baseline, not proof of a live production deployment. Host hardening, TLS termination, DNS/firewall policy, secret-manager integration, off-host backups, monitoring, restore drills and runbooks remain operator responsibilities. Nuclei stays blocked in production until isolated scanner execution is deployed.


## SOC engine health indicators

The Overview and Integrations workspaces display backend-reported health for Wazuh Manager, Wazuh Indexer, CrowdSec, Nuclei and Shannon. Nuclei and Shannon status is retrieved from their authenticated health endpoints; it is not hard-coded as unavailable.

Only administrators and analysts can request Nuclei and Shannon health details. Viewer accounts see a restricted indicator because the corresponding endpoints are role-protected. Use the dashboard **Refresh** action to recheck the health endpoints.

A healthy indicator means the relevant backend health check succeeded and execution is enabled where applicable. It does **not** prove that a scan has completed, findings have been ingested, or a production deployment is healthy. An unavailable health request is shown as unknown, not as not configured.

See [Engine Health Indicators](docs/ENGINE_HEALTH.md) for the status meanings and troubleshooting steps.


## API perimeter hardening

The API validates incoming Host headers against `OPS_AEGIS_ALLOWED_HOSTS`, separately from browser CORS policy. Production requires an explicit comma-separated allowlist of lowercase hostnames/IP addresses without schemes, ports or wildcards. Configure the public reverse-proxy hostname and `127.0.0.1` for the container-local API health check. API responses include restrictive browser security headers, and authentication routes are marked `no-store`. See [API perimeter security](docs/API_PERIMETER_SECURITY.md) and [production deployment](docs/PRODUCTION_DEPLOYMENT.md).


## Preflight checks before opening a pull request

Run the same high-value startup and deployment checks locally before pushing changes that touch configuration, migrations or Compose:

```powershell
# From the repository root
if (-not (Test-Path .env.production)) { Copy-Item .env.production.example .env.production }
docker compose --env-file .env.production.example -f compose.production.yaml config --quiet

# Backend import and migration checks
Push-Location backend
python -c "from app.config import Settings, settings; from app.main import app; assert isinstance(settings, Settings); print(app.title)"
$env:DATABASE_URL = "sqlite:///./preflight-migrations.db"
alembic upgrade head
pytest -q
Remove-Item Env:DATABASE_URL
Pop-Location

# Frontend checks
Push-Location frontend
npm test
npm run build
Pop-Location
```

The CI workflow now runs a dedicated preflight job first. It verifies the shared settings export, imports the FastAPI application, applies the full Alembic migration chain to a disposable SQLite database, and validates the production Compose file before the backend, frontend, runner and container jobs can start. A failed preflight blocks all downstream jobs. These checks reduce configuration regressions; they do not replace review or live deployment validation.


## Live integration diagnostics

Use the read-only operator validation script to check database/Redis reachability, detection and isolated Nuclei worker heartbeats, and configured Wazuh Manager, Wazuh Indexer, CrowdSec and Shannon endpoints. It never launches scans or changes application data:

\`\`\`powershell
python backend/scripts/validate_integrations.py --env-file .env --output artifacts/integration-diagnostics.json
\`\`\`

Add \`--include-nvd\` only when you want one read-only lookup of a fixed public CVE. VirusTotal and AbuseIPDB are not queried, so this check does not consume their API quota. See [Live Integration Validation](docs/INTEGRATION_VALIDATION.md) for status meanings, safety boundaries and troubleshooting. See the [Phase 5 staging execution checklist](docs/PHASE5_EXECUTION_CHECKLIST.md) and [staging evidence register](docs/PHASE5_STAGING_EVIDENCE.md) for the production-readiness exit criteria. A successful health check is not proof of telemetry ingestion or production readiness.


## Automated security checks

Pull requests and pushes to \`main\` run a separate security workflow:
- Full Git-history secret scanning with Gitleaks.
- Vulnerability audits of backend and Shannon bridge Python dependencies.
- Strict vulnerability audits of the declared Python dependency sets.

See [Security Scanning in CI](docs/SECURITY_SCANNING.md) for remediation steps and limitations. A green scan does not prove that previously exposed credentials were rotated or that a deployed environment is secure.
