# OpsAegis

**Operational Security & Incident Governance System**

A unified security operations and threat-response platform integrating Wazuh, CrowdSec, Nuclei and Shannon through an independent orchestration, normalization, correlation and incident-management layer.

## Current implementation

- FastAPI backend, PostgreSQL persistence, Redis service, Alembic migrations and JWT/RBAC.
- Authenticated React/TypeScript operational workspace (PR #5).
- Wazuh Indexer read-only alert ingestion with source-event deduplication.
- CrowdSec Local API read-only active-decision ingestion (PR #6).
- No fabricated alerts, live metrics or engine connectivity claims.

A built adapter is not proof of a live connection. Configure and verify each authorized engine endpoint before expecting its records.

## Security engines

| Engine | Role | Integration status |
|---|---|---|
| Wazuh | Endpoint telemetry and SIEM alerts | Indexer read-only adapter |
| CrowdSec | Behavioural threat decisions | LAPI active-decision adapter |
| Nuclei | Authorized vulnerability scanning | Authorized target registry and safe-profile scans |
| Shannon | Authorized AI-assisted application testing | External isolated-runner control-plane adapter (runner deployment required) |

## CrowdSec Local API integration

OpsAegis reads CrowdSec Local API endpoint /v1/decisions using a bouncer API key in the X-Api-Key header. Bouncer credentials grant read-only decision access. OpsAegis does not create, delete or enforce decisions.

Configure the backend .env:

| Variable | Purpose |
|---|---|
| CROWDSEC_LAPI_URL | HTTPS Local API base URL, e.g. https://crowdsec.internal:8080 |
| CROWDSEC_API_KEY | Dedicated bouncer API key |
| CROWDSEC_CA_CERT | Optional trusted CA certificate path |
| CROWDSEC_TIMEOUT_SECONDS | Request timeout, 1–60 seconds |
| CROWDSEC_MAX_RESULTS | Maximum decisions per collection, 1–1000 |

Create a dedicated key on the CrowdSec host with the command cscli bouncers add opsaegis-readonly. Store the generated key only in the backend environment. Do not use machine login/password credentials or frontend variables.

After configuration, restart the backend. Authenticated admin/analyst endpoints:

- GET /api/v1/integrations/crowdsec/health
- POST /api/v1/integrations/crowdsec/collect

Collection imports active decisions, not the complete CrowdSec alert history. It retains decision ID, scope, value, action, scenario, origin and duration as bounded evidence. The current LAPI decision response does not provide a reliable event timestamp, so ingestion time is used as observation time. Repeated collection deduplicates by decision ID and preserves analyst triage status. Collection is manual/pull-based; scheduled polling is not yet implemented.

## Wazuh Indexer integration

Configure backend-only WAZUH_INDEXER_URL, WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD, optional WAZUH_INDEXER_CA_CERT, WAZUH_INDEXER_TIMEOUT_SECONDS and WAZUH_INDEXER_MAX_RESULTS. Use a dedicated read-only Indexer account, HTTPS and certificate verification. Endpoints: GET /api/v1/integrations/wazuh/health and POST /api/v1/integrations/wazuh/collect.

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

See docs/PROJECT_STATUS.md and docs/SECURITY_BASELINE.md for implementation boundaries.

## Nuclei authorized scanning

Nuclei is disabled by default. Install the Nuclei binary in the backend runtime and set NUCLEI_ENABLED=true only after deployment hardening. Admins register exact HTTPS targets with an authorization reference; admins and analysts can list targets and scan history and start the fixed safe profile. API endpoints: GET /api/v1/integrations/nuclei/health, GET /targets, POST /targets, POST /targets/{id}/scans and GET /scans under the integrations/nuclei prefix.

The API accepts no arbitrary CLI flags, template paths or free-form scan URLs. The fixed profile disables Interactsh and update checks, bounds rate/concurrency/runtime/output and excludes DoS, fuzzing, intrusive and headless template tags. Findings are deduplicated; analyst triage state is preserved. Only scan systems for which you have written authorization.

Deployment limitation: Nuclei currently runs as a subprocess inside the backend runtime, not a hardened isolated worker. Keep it disabled until deployed in a dedicated unprivileged container with resource limits and network egress restrictions. No live scan is claimed.


## Shannon authorized application testing

OpsAegis provides an authenticated control-plane adapter for a separately deployed Shannon runner bridge. Shannon OSS is a CLI/worker orchestrator, not a native HTTP API; OpsAegis does not execute Shannon inside FastAPI or expose the Docker socket to the backend.

See [docs/SHANNON_RUNNER.md](docs/SHANNON_RUNNER.md) for the bridge API contract, deployment boundary, security requirements and licensing notes. Shannon OSS is AGPL-3.0; its source is not embedded in this repository.

The integration is disabled by default. Configure backend-only SHANNON_ENABLED, SHANNON_RUNNER_URL and SHANNON_RUNNER_TOKEN only after deploying and reviewing the isolated bridge. Admins register an HTTPS staging target, its GitHub source repository and a written authorization reference. Only admins can dispatch an assessment. Analysts can view and sync scan history.

Findings are accepted only when the bridge reports validation_status=exploited and supplies non-empty proof evidence. Repeated results are deduplicated and analyst triage state is preserved. A configured adapter is not proof of a live Shannon engine: no bridge, model-provider key or live scan is included in this PR.

Shannon actively exploits applications and may mutate state. Use disposable lab/staging environments only; never production. The runner must enforce DNS/IP egress allowlists, isolation, resource budgets, read-only source mounts and prompt-injection safeguards.


## Shannon isolated runner deployment

PR #9 adds a separate reference bridge under [runner/shannon-bridge](runner/shannon-bridge/README.md). It is not part of the OpsAegis backend container or the local Docker Compose stack. Deploy only on a dedicated disposable Linux VM with an independently enforced egress firewall/proxy, exact target and repository allowlists, a pinned Shannon CLI and written staging authorization. The bridge remains disabled by default. See [the runner deployment contract](docs/SHANNON_RUNNER.md).

The bridge is a controlled single-job validation implementation, not an HA production queue. Job state is in memory; cancellation, durable retries, artifact download and a full report parser are not implemented. SARIF ingestion fails closed unless explicit proof metadata and an in-scope affected URL exist. CI does not run Shannon. No live pentest or live engine connection is claimed.
