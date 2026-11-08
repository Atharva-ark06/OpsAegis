# OpsAegis — Project Status

Updated for the Stage 3 milestones merged through PR #3 and the proposed Wazuh integration work in PR #4.

## Implemented and merged

### Stage 3 foundation
- FastAPI application, root/health/readiness endpoints and environment-based configuration.
- Initial SQLAlchemy models for assets, findings and incidents.
- React + TypeScript analyst-console starter.
- Docker Compose definitions for API, frontend, PostgreSQL and Redis.

### Database persistence
- SQLAlchemy session lifecycle and persistence APIs for assets, findings and incidents.
- Alembic initial schema migration.
- PostgreSQL and Redis service definitions with health checks.

### Authentication and access control (PR #3)
- JWT bearer authentication and Argon2 password hashing.
- Admin, analyst and viewer roles enforced in protected API routes.
- Administrator user provisioning and first-admin bootstrap command.
- User and audit-log models; successful login and user creation audit events.
- Production signing-secret validation and configurable token lifetime.

## PR #4 — Wazuh integration implementation

This PR introduces:
- Wazuh Indexer/OpenSearch read-only adapter using backend-only Basic Auth over HTTPS.
- TLS verification, optional CA bundle, request timeout and bounded result count.
- Normalization of alert IDs, timestamps, rule levels, descriptions and agent metadata.
- Protected integration health and collection endpoints for admin/analyst roles.
- Persisted finding evidence metadata and source-event deduplication migration.
- Collection audit event and adapter/route tests using mocked HTTP responses.

**The adapter code does not mean a live Wazuh instance is connected.** Live validation requires an authorized Wazuh Indexer URL and read-only credentials in the backend environment.

## Not implemented yet

- Scheduled polling/Redis worker orchestration and retry/dead-letter handling.
- CrowdSec, Nuclei and Shannon adapters.
- Full pagination/cursor-based collection beyond the configured Wazuh result cap.
- Asset auto-mapping and cross-engine correlation.
- Incident generation from correlated findings and complete incident lifecycle.
- Evidence object storage and evidence access controls.
- Production deployment hardening, monitoring and operational runbooks.

## Data integrity and UI principles

- Never present fixtures or mock responses as live telemetry.
- Preserve source engine and source-native event identifiers.
- Deduplicate repeated source events rather than multiplying findings.
- Do not silently overwrite analyst triage status during ingestion.
- Keep integration credentials server-side and never return them in API responses.

## Current validation status

Automated tests cover the adapter's normalization, transport configuration, bounded queries, access control and idempotent ingestion behavior. CI results must be checked against the latest PR commit; no live Wazuh connection is claimed until tested against an authorized lab Indexer.
