# OpsAegis

**Operational Security & Incident Governance System**

A unified security operations and threat-response platform integrating Wazuh, CrowdSec, Nuclei and Shannon through an independent orchestration, normalization, correlation and incident-management layer.

> OpsAegis does not replace these engines. It connects them and provides a shared operational workflow.

## Development status

Stage 3 foundation and database persistence are merged. This branch adds JWT authentication, role-based authorization, password hashing, administrator provisioning and audit-event storage. Changes remain subject to review and CI validation.

**No live engine integration is claimed until the adapter is implemented, configured and verified against the real engine.** No fabricated alerts or telemetry will be presented as live data.

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
- Background queue: Redis
- Evidence: MinIO or local object storage
- Deployment: Docker Compose on Linux
- Reverse proxy: Caddy or Nginx (selection pending)

## Security principles

- Use authorized assets and targets only.
- Keep credentials out of source control and frontend code.
- Isolate scanning and testing workers with network, time and resource limits.
- Restrict Shannon to explicitly authorized lab/staging environments initially.
- Require policy and authorization for disruptive actions such as blocking.

See `docs/` for architecture, project status and security baseline documentation.
## Authentication and access control (PR #3)

The API uses short-lived JWT bearer tokens and three roles:

| Role | Permissions |
|---|---|
| `admin` | Read data, create assets/findings/incidents, manage users, read audit events |
| `analyst` | Read data and create assets/findings/incidents |
| `viewer` | Read-only access |

Passwords are hashed with Argon2 through `pwdlib`. User creation is restricted to administrators. The first administrator is provisioned from the backend container after database migrations:

```bash
docker compose exec backend python -m app.bootstrap_admin
```

The command refuses to create another bootstrap administrator if any account already exists. Keep the initial credentials private.

### Authentication API

- `POST /api/v1/auth/login` — exchange email/password for a bearer token.
- `GET /api/v1/auth/me` — return the authenticated account.
- `POST /api/v1/auth/users` — administrator-only account creation.
- `GET /api/v1/auth/audit` — administrator-only audit-event listing.

Send the returned token as `Authorization: Bearer <token>`. Access tokens are short-lived; re-authenticate after expiry. Token revocation/refresh and account recovery are not implemented in this milestone.

### Production configuration

Set a unique random `OPS_AEGIS_SECRET_KEY` with at least 32 characters and set `OPS_AEGIS_ENV=production`. The application rejects the development secret in production. Never commit the real `.env` file.
