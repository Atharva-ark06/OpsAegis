# OpsAegis — Project Status

## Implemented and merged
- FastAPI, PostgreSQL, Alembic, Redis, JWT/RBAC and audit logging.
- Authenticated React/TypeScript workspace.
- Wazuh Indexer read-only alert ingestion.
- CrowdSec Local API read-only active-decision ingestion.
- Nuclei authorized-target registry, fixed safe-profile CLI execution, scan history and JSONL finding normalization.

## Nuclei boundaries
- Admin-only target registration with a required authorization reference.
- Exact HTTPS URLs only; reject credentials, query/fragment, localhost, metadata, loopback, link-local, multicast and reserved IP targets.
- Only enabled registered targets can be scanned. No arbitrary CLI flags, template paths or user-supplied scan targets.
- Fixed profile disables Interactsh/update checks, bounds rate, concurrency, runtime and output, and excludes DoS/fuzz/intrusive/headless templates.
- Findings deduplicate by template ID + matched URL + matcher name and preserve analyst triage.
- Disabled by default; install Nuclei and explicitly set NUCLEI_ENABLED=true.
- This executes in the backend runtime, not an isolated worker. Production must use a dedicated unprivileged scanner container with resource and egress limits before enabling.

## Remaining
- Dedicated scanner worker/queue, scheduled scans, cancellation and durable retries.
- Shannon integration, CrowdSec historical alerts, full pagination, asset auto-mapping, cross-engine correlation, incident lifecycle, Wazuh Manager and response actions.
- Production secrets management, monitoring and operational runbooks.

No live Nuclei scan or engine connection is claimed. Live validation requires explicit written authorization.
