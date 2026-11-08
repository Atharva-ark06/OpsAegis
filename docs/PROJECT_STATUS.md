# OpsAegis — Stage 3 Foundation

## Included
- FastAPI application and root, health and readiness endpoints.
- Environment-based configuration.
- Initial SQLAlchemy models for assets, findings and incidents.
- Normalized-finding data contract and engine adapter protocol.
- React + TypeScript analyst-console starter.
- Docker Compose definitions for API, frontend, PostgreSQL and Redis.
- Initial API tests.

## Not implemented
- Database session lifecycle, migrations and persistence APIs.
- Authentication, JWT issuance and RBAC enforcement.
- Redis worker process and job execution.
- Real Wazuh, CrowdSec, Nuclei or Shannon adapters.
- Normalization pipeline, correlation logic and incident CRUD.
- Evidence access controls and production deployment hardening.

The interface labels integrations as planned and contains no fabricated live telemetry.
