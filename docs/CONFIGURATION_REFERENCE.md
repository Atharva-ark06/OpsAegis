# Configuration and secret handling

## Rules

- Keep credentials on the backend or in a secret manager.
- Do not add API keys to frontend `VITE_*` variables.
- Do not commit `.env`, `.env.production`, certificates containing private keys, backups or incident evidence.
- Use unique secrets for API signing, worker authentication, PostgreSQL and Redis.
- Use TLS with certificate verification for remote providers.
- Prefer dedicated read-only provider accounts.
- Rotate a credential immediately if it is exposed; deleting it from a commit does not revoke it.

## Core runtime settings

| Variable | Scope | Notes |
|---|---|---|
| `OPS_AEGIS_ENV` | API/worker | Set to `production` in production environments |
| `OPS_AEGIS_SECRET_KEY` | API | Unique signing secret; never reuse the worker key |
| `OPS_AEGIS_WORKER_SECRET_KEY` | Worker | Separate worker validation secret |
| `OPS_AEGIS_BOOTSTRAP_TOKEN` | API, temporary | Used only for first-admin bootstrap; remove/rotate after setup |
| `DATABASE_URL` | API/worker | PostgreSQL connection string |
| `REDIS_URL` | API/worker | Authenticated Redis connection string |
| `CORS_ORIGINS` | API | Exact browser origins; HTTPS in production |
| `OPS_AEGIS_ALLOWED_HOSTS` | API | Explicit host allowlist, without scheme or port |

## Integration credentials

| Variables | Provider | Scope |
|---|---|---|
| `WAZUH_MANAGER_URL`, `WAZUH_MANAGER_USERNAME`, `WAZUH_MANAGER_PASSWORD`, `WAZUH_MANAGER_CA_CERT` | Wazuh Manager | API |
| `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD`, `WAZUH_INDEXER_CA_CERT` | Wazuh Indexer | API and the specifically configured Wazuh collection process |
| `CROWDSEC_LAPI_URL`, `CROWDSEC_API_KEY`, `CROWDSEC_CA_CERT` | CrowdSec decisions | API |
| `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD` | CrowdSec alert history | API; optional, broader permission risk |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Threat intelligence | API only |
| `NVD_API_KEY` | NVD | API only; optional |
| `SHANNON_ENABLED`, `SHANNON_RUNNER_URL`, `SHANNON_RUNNER_TOKEN` | Shannon bridge | API only; disabled until isolated runner is reviewed |

Nuclei configuration is described in [the Nuclei worker guide](NUCLEI_WORKER.md). Do not enable scanner flags until the isolated worker and external egress policy are independently verified.

## Optional tuning

The root `.env.example` lists supported defaults for request timeouts, result bounds, cache lifetime, evidence storage and provider settings. Keep defaults unless there is an operational reason to change them. Validate values against the corresponding adapter/configuration code before adding new variables.

## Railway variable hygiene

Add credentials to the appropriate Railway service only. The API needs provider credentials; the frontend does not. Workers should receive only the subset of secrets they actually require. Never include secret values in screenshots, logs, PR descriptions or support messages.

## Local and production templates

- `.env.example`: local development only; deliberately unsafe defaults.
- `.env.production.example`: production Compose template with placeholders; replace every placeholder before startup.
- Railway variables: configured per service in the Railway environment.

See [security baseline](SECURITY_BASELINE.md) and [production deployment](PRODUCTION_DEPLOYMENT.md).
