# OpsAegis — Project Status

Updated for merged PRs #3, #4 and #5 and the PR #6 CrowdSec adapter implementation.

## Implemented and merged
- FastAPI application, PostgreSQL persistence, Alembic migrations and Redis service.
- JWT bearer authentication, Argon2 password hashing, admin/analyst/viewer RBAC and audit logging.
- Authenticated React/TypeScript workspace with API-backed assets, findings, incidents and Wazuh status.
- Wazuh Indexer HTTPS read-only adapter, bounded alert retrieval, normalization, evidence metadata and source-event deduplication.

## PR #6 — CrowdSec Local API adapter
- Uses CrowdSec Local API /v1/decisions with a dedicated bouncer API key in X-Api-Key.
- Enforces HTTPS, certificate verification, optional CA bundle, timeout, disabled redirects and bounded result count.
- Imports active decisions only; does not claim historical CrowdSec alert ingestion.
- Normalizes decision ID, action, scope, value, scenario, origin and duration.
- Adds protected admin/analyst health and manual collection endpoints.
- Deduplicates by decision ID and preserves analyst triage status and first-seen time.
- Audits collection counts without storing API keys or raw upstream responses.
- Adds deterministic adapter and route tests.

A configured endpoint is not proof of a live connection. CI uses mocked HTTP responses; live verification requires an operator-supplied authorized LAPI URL and bouncer key.

## Not implemented yet
- Scheduled polling, durable Redis worker orchestration, retry/backoff and persisted execution history.
- CrowdSec historical alert ingestion; current adapter reads active decisions only.
- Nuclei scan orchestration, target authorization registry, scan profiles and finding ingestion.
- Shannon isolated job execution and evidence ingestion.
- Full pagination/cursor collection and asset auto-mapping.
- Cross-engine correlation, automatic incident creation and complete incident lifecycle.
- Wazuh Manager agent-management integration and response actions.
- Production deployment hardening, monitoring, secrets manager integration and operational runbooks.

## Data integrity and UI principles
- Never present fixtures or mock responses as live telemetry.
- Preserve source engine and source-native event identifiers.
- Deduplicate repeated source events rather than multiplying findings.
- Do not silently overwrite analyst triage status during ingestion.
- Keep integration credentials server-side and never return them in API responses.
- Distinguish active CrowdSec decisions from historical alerts and enforcement.

## Validation
PR #6 adds mocked tests for CrowdSec LAPI authentication, HTTPS validation, malformed responses, normalization, role authorization, deduplication and triage preservation. Full backend/frontend CI and an authorized live CrowdSec lab check are required before claiming production readiness.
