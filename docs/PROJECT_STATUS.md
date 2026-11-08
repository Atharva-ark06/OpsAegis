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

## Incident response workflow (PR #10)
- Finding status updates are available to admins and analysts and create audit records.
- Incident lifecycle is constrained to open, investigating, contained, resolved and closed states.
- Incidents support active admin/analyst assignment, required resolution notes for resolved/closed states, timestamps and audit records.
- Viewers remain read-only; dashboard controls are role-gated.

## Security correlation engine (PR #11)
- Deterministic rules correlate persisted findings only: repeated Wazuh authentication alerts per identified agent, matching Wazuh agent IP plus CrowdSec active IP/range decision, and target-origin overlap between Nuclei and proof-validated Shannon findings.
- Bounded evaluation window and authentication threshold; false-positive findings are excluded.
- Correlated detections retain source finding IDs, evidence, stable fingerprints and incident linkage. Re-evaluation refreshes the existing detection instead of creating duplicate incidents.
- Detection evaluation and automatic incident creation are audited; viewers can read detections/rules but cannot run evaluation.
- No AI/ML inference, raw event stream, scheduled evaluation, editable rule administration or live engine verification is included. Nuclei/Shannon origin overlap is target-level corroboration, not proof of an identical vulnerability.

## Scheduled detection and alert lifecycle (PR #12)
- Dedicated Redis-backed worker schedules evaluations from a persisted administrator-controlled configuration; disabled by default.
- Queue uses a renewable single-worker lease, durable run rows, startup recovery and up to three attempts with exponential backoff.
- Detection lifecycle: new → acknowledged → investigating → resolved, with audited transitions.
- High/critical detections create per-user in-app notifications for active administrators and analysts; notification reads are user-scoped.
- Worker evaluates only already-persisted findings; it does not collect telemetry, execute scans or send email/SMS/external pages.
- Live Redis worker operation and production scheduling have not been independently validated.

## Remaining
- Dedicated scanner worker/queue, scheduled scans, cancellation and durable retries.
- Deploy and independently validate the Shannon bridge on a dedicated disposable VM. The bridge is a controlled single-job reference implementation; job state is in memory, and durable queueing, cancellation, retries, artifact download and full report parsing remain outstanding. No live scan is claimed.
- CrowdSec historical alerts, full pagination, asset auto-mapping, cross-engine correlation, incident lifecycle, Wazuh Manager and response actions.
- Production secrets management, monitoring and operational runbooks.

No live Nuclei scan or engine connection is claimed. Live validation requires explicit written authorization.

See docs/SHANNON_RUNNER.md for runner requirements and limitations. Shannon remains disabled until the external HTTPS runner is configured and health-checked.
\n\nThe Shannon bridge is not production-ready. Do not enable it until independent egress enforcement, DNS-rebinding defenses, VM isolation, provider budget limits and written staging authorization have been verified.\n

## Threat intelligence / IOC enrichment (PR #13)
- Read-only, on-demand VirusTotal and AbuseIPDB adapters with server-side credentials, TLS verification, fixed provider origins, no redirects, disabled environment proxy inheritance and bounded timeouts.
- Supported indicators: public IP, domain, HTTP(S) URL and MD5/SHA-1/SHA-256/SHA-512 file hash. Private/reserved addresses, local domains and malformed indicators are rejected.
- AbuseIPDB is IP-only; it explicitly reports not-applicable for other IOC types.
- Provider responses are reduced to normalized verdicts, source-derived scores and selected metadata; raw provider payloads and secrets are not returned.
- IOC records are deduplicated by type/value hash, cached for a configurable TTL, force-refreshable by operators and audit logged.
- Provider errors, rate limits, missing records and missing configuration remain distinct; unavailable provider data is never presented as clean.
- Lookups do not submit URLs/files for scanning, fetch the indicator itself, block traffic or execute response actions.
- Live provider calls require operator-supplied API keys; no keys or live lookup validation are included.


## Asset and endpoint identity (PR #14)
- Wazuh findings with an identified agent ID create or update one source-scoped endpoint asset.
- New findings link to the corresponding endpoint; existing analyst-selected asset assignments are preserved.
- Asset API exposes source engine, external ID, observed IP, agent observation state and last-seen time.
- Source refresh does not overwrite analyst-managed asset type or environment.
- Alert-observed inventory only: no claim of Wazuh Manager online status, OS inventory or silent-agent discovery. CrowdSec IP-only records are not auto-mapped.
