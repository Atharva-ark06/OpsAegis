# OpsAegis — Project Status

## Implemented and merged
- FastAPI, PostgreSQL, Alembic, Redis, JWT/RBAC and audit logging.
- Authenticated React/TypeScript workspace.
- Wazuh Indexer read-only alert ingestion.
- CrowdSec Local API read-only active-decision ingestion.
- Nuclei authorized-target registry, fixed safe-profile CLI execution, scan history and JSONL finding normalization.
- Shannon external isolated-runner control-plane adapter, authorized target registry, scan dispatch/history, proof-gated finding ingestion and audit logging.\n- Separate Shannon bridge reference implementation with exact allowlists, pinned CLI, authenticated API, fail-closed SARIF proof gate and disabled-by-default execution.

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
- Deploy and independently validate the Shannon bridge on a dedicated disposable VM. The bridge is a controlled single-job reference implementation; job state is in memory, and durable queueing, cancellation, retries, artifact download and full report parsing remain outstanding. No live scan is claimed.
- CrowdSec historical alerts, full pagination, asset auto-mapping, cross-engine correlation, incident lifecycle, Wazuh Manager and response actions.
- Production secrets management, monitoring and operational runbooks.

No live Nuclei scan or engine connection is claimed. Live validation requires explicit written authorization.

See docs/SHANNON_RUNNER.md for runner requirements and limitations. Shannon remains disabled until the external HTTPS runner is configured and health-checked.
\n\nThe Shannon bridge is not production-ready. Do not enable it until independent egress enforcement, DNS-rebinding defenses, VM isolation, provider budget limits and written staging authorization have been verified.\n