# OpsAegis

**Operational Security & Incident Governance System**

A unified security operations and threat-response platform integrating Wazuh, CrowdSec, Nuclei and Shannon through an independent orchestration, normalization, correlation and incident-management layer.

> OpsAegis does not replace these engines. It connects them and provides a shared operational workflow.

## Development status

The Stage 3 foundation, database persistence and authentication/RBAC milestones have been merged. PR #4 introduces the first real integration adapter: read-only alert collection from the Wazuh Indexer, normalized finding persistence, and authenticated integration health/collection endpoints.

**A working adapter does not mean a live connection is configured.** Wazuh data is only real when an operator configures an authorized Indexer endpoint and credentials. No fabricated alerts or telemetry are presented as live data.

## Authenticated frontend workspace (PR #5)

The frontend now includes a real sign-in flow and authenticated operational views backed by the API:
- Session-scoped JWT storage in browser `sessionStorage`; the token is sent only in the Authorization header and is cleared on sign-out or a 401 response.
- Authenticated `/auth/me` session verification.
- Database-backed asset, finding and incident lists and overview counts (up to the API's current 200-record list limit per resource).
- Role-aware Wazuh health and collection controls for administrators and analysts; viewers do not call the restricted integration endpoints.
- Loading, empty, partial-error, refresh and responsive states. No fabricated operational metrics are used.
- Frontend API base URL defaults to `http://localhost:8000/api/v1`. Set `VITE_API_BASE_URL` at frontend build time when the API is hosted elsewhere. This variable is a public URL, never a secret.

The browser session token is accessible to JavaScript in the page and is not a substitute for XSS prevention or a server-side revocation mechanism. The current backend has no token refresh or logout/revocation endpoint; signing out clears the browser's copy and tokens expire according to the configured access-token lifetime.

Frontend checks:
```bash
cd frontend
npm install
npm test
npm run build
```

## Security engines

| Engine | Responsibility |
|---|---|
| Wazuh | Endpoint monitoring, security events and SIEM/XDR alerts |
| CrowdSec | Threat intelligence decisions and bouncer-based enforcement |
| Nuclei | Authorized vulnerability and misconfiguration scanning |
| Shannon | AI-assisted application penetration testing in authorized lab/staging environments |

## Planned application stack

- Frontend: React + TypeScript
- Backend: Python + FastAPI
- Database: PostgreSQL
- Background queue: Redis (worker orchestration remains future work)
- Evidence: structured metadata is stored with findings; external evidence storage remains planned
- Deployment: Docker Compose on Linux
- Reverse proxy: Caddy or Nginx (selection pending)

## Security principles

- Use authorized assets and targets only.
- Keep credentials out of source control and frontend code.
- Use a dedicated read-only Wazuh Indexer account.
- Require HTTPS and TLS verification for Indexer connections.
- Bound collection windows, request timeouts and result counts.
- Isolate scanning and testing workers with network, time and resource limits.
- Restrict Shannon to explicitly authorized lab/staging environments initially.
- Require policy and authorization for disruptive actions such as blocking.

## Authentication and access control

The API uses short-lived JWT bearer tokens and three roles:

| Role | Permissions |
|---|---|
| `admin` | Read data, create assets/findings/incidents, manage users, read audit events and run integrations |
| `analyst` | Read data, create assets/findings/incidents and run integrations |
| `viewer` | Read-only access to operational data |

Passwords are hashed with Argon2 through `pwdlib`. User creation is restricted to administrators. The first administrator is provisioned from the backend container after database migrations:

```bash
docker compose exec backend python -m app.bootstrap_admin
```

### Authentication API

- `POST /api/v1/auth/login` — exchange email/password for a bearer token.
- `GET /api/v1/auth/me` — return the authenticated account.
- `POST /api/v1/auth/users` — administrator-only account creation.
- `GET /api/v1/auth/audit` — administrator-only audit-event listing.

Send the returned token as `Authorization: Bearer <token>`. Access tokens are short-lived; re-authenticate after expiry. Token revocation/refresh and account recovery are not implemented in this milestone.

## Wazuh Indexer integration (PR #4)

OpsAegis queries the **Wazuh Indexer/OpenSearch API** for alert documents. It does not confuse the Indexer with the Wazuh Manager API and does not issue response actions or block agents.

Configure these variables in the backend `.env`:

| Variable | Purpose |
|---|---|
| `WAZUH_INDEXER_URL` | HTTPS base URL, for example `https://wazuh-indexer.example:9200` |
| `WAZUH_INDEXER_USERNAME` | Dedicated read-only Indexer username |
| `WAZUH_INDEXER_PASSWORD` | Read-only account password |
| `WAZUH_INDEXER_INDEX_PATTERN` | Defaults to `wazuh-alerts-*` |
| `WAZUH_INDEXER_CA_CERT` | Optional trusted CA certificate path |
| `WAZUH_INDEXER_TIMEOUT_SECONDS` | Request timeout, 1–60 seconds |
| `WAZUH_INDEXER_MAX_RESULTS` | Maximum alerts per collection, 1–1000 |

Do not put these credentials in frontend variables, source control, screenshots or API responses. Use a dedicated account with only the read permissions required to query alert indices. For an internal/self-signed CA, configure the CA certificate. This adapter does not provide a TLS-verification bypass.

Apply the new database migration before using collection:

```bash
cd backend
alembic upgrade head
```

### Integration endpoints

Both endpoints require an authenticated `admin` or `analyst` bearer token:

- `GET /api/v1/integrations/wazuh/health` — reports `not_configured`, `healthy` or `unhealthy` without disclosing credentials.
- `POST /api/v1/integrations/wazuh/collect` — fetches alerts from the last 15 minutes by default. An optional timezone-aware `since` query parameter can request a window no older than 30 days.

Collection maps Wazuh rule levels to normalized severity, stores a bounded set of agent/rule metadata, and deduplicates repeated documents by the Indexer document ID. Repeated collection updates `last_seen_at` rather than creating another finding. Full log payloads are deliberately not copied into evidence metadata.

Example:

```bash
curl -X POST "http://localhost:8000/api/v1/integrations/wazuh/collect" \
  -H "Authorization: Bearer $TOKEN"
```

A successful API response only confirms the adapter request and database ingestion completed. It does not claim that Wazuh is configured unless the health endpoint reports it. The current adapter is pull-based and bounded; scheduled polling, pagination beyond the configured result cap, asset auto-mapping, correlation and other engines remain future work.

### Production configuration

Set a unique random `OPS_AEGIS_SECRET_KEY` with at least 32 characters and set `OPS_AEGIS_ENV=production`. The application rejects the development secret in production. Never commit the real `.env` file.

See `docs/PROJECT_STATUS.md` and `docs/SECURITY_BASELINE.md` for the current implementation state.
