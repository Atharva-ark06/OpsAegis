# OpsAegis

**Operational Security & Incident Governance System**

A unified security operations and threat-response platform integrating Wazuh, CrowdSec, Nuclei and Shannon through an independent orchestration, normalization, correlation and incident-management layer.

> OpsAegis does not replace these engines. It connects them and provides a shared operational workflow.

## Development status

Stage 3 has started. The initial foundation will include a FastAPI backend, React + TypeScript frontend, PostgreSQL, Redis, Docker Compose, integration contracts and automated tests.

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