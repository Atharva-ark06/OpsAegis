# Phase 5 staging execution checklist

This is the operator runbook for closing Phase 5. Use a disposable staging environment, not production. Keep scanner engines disabled unless their separate safety gates below have been independently met.

## 1. Preconditions

- A staging host/VM with Docker Engine and Compose v2.
- A staging PostgreSQL/Redis data store, or the isolated production Compose stack.
- Operator-owned Wazuh Manager, Wazuh Indexer and CrowdSec test integrations where those services are in scope.
- A disposable Wazuh lab agent and known test events.
- A written authorization record for any scanner target. Do not use a public or third-party target.
- A protected location for sanitized reports. Never commit `.env.production`, raw telemetry, credentials, tokens or unredacted reports.

Prepare the environment using [Production deployment](PRODUCTION_DEPLOYMENT.md). Use unique secrets and TLS at the staging reverse proxy. Confirm that ports 8000, 5432 and 6379 are not public.

## 2. Deploy and prove service readiness

From the repository root:

```powershell
docker compose --env-file .env.production -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.production.yaml up -d --build
docker compose --env-file .env.production -f compose.production.yaml ps
```

Require PostgreSQL, Redis, backend, detection-worker and frontend to report healthy. Confirm the one-shot `migrate` service exited with code 0. Check the frontend health endpoint and API readiness through the frontend reverse proxy:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/api/v1/ready
```

The API readiness response must report `status=ready`, `database=ok` and `redis=ok`. Record the image tags/digests, migration revision and sanitized service status.

## 3. Run strict read-only integration diagnostics

```powershell
python backend/scripts/validate_integrations.py --env-file .env.production --strict --output artifacts/phase5-integration-diagnostics.json
```

Exit code 0 means all checks that were actually probed passed; intentionally unconfigured/disabled checks may be skipped. Exit code 1 means a check or configuration failed. Exit code 3 means at least one configured check was not probed or no meaningful integration checks ran. Do not treat `skipped` or `not_probed` as a live pass.

The diagnostic does not send IOC lookups to VirusTotal/AbuseIPDB, does not scan targets, and does not modify configuration or application data. Add `--include-nvd` only when one fixed public NVD lookup is approved.

## 4. Validate real integration ingestion

Use a disposable lab identity and bounded time window. Authenticate as an administrator or analyst. For each enabled integration:

- **Wazuh Manager:** call `POST /api/v1/integrations/wazuh-manager/sync`; compare the observed agent IDs, names, IPs, OS, status and last keep-alive with the lab Manager. Include an agent with no alert. Confirm analyst-managed asset fields are preserved.
- **Wazuh Indexer alerts:** generate known lab authentication events, then call `POST /api/v1/integrations/wazuh/collect?since=<RFC3339-UTC>`. Verify the source document IDs, timestamps, received/inserted/updated counts and duplicate behavior.
- **Wazuh Vulnerability Detector:** call `POST /api/v1/integrations/wazuh-vulnerabilities/sync` against known lab package/CVE data. Verify exact agent mapping, package provenance, truncation and preservation of analyst remediation state.
- **CrowdSec:** use an approved short-lived test decision, call `POST /api/v1/integrations/crowdsec/collect` twice, and verify deduplication and audit records. Verify OpsAegis does not create, delete or enforce decisions.
- **Threat intelligence:** use operator-selected public indicators and monitor provider quotas. Confirm normalized output and sanitized audit records. Never submit files or URLs for scanning as part of this check.

A successful adapter health request alone is not proof that ingestion works. Record counts and source identities, not raw sensitive payloads.

## 5. Prove detection-to-incident-to-notification

1. Generate at least three known Wazuh authentication failures for one disposable lab agent inside a 15-minute window.
2. Collect those events from Wazuh Indexer.
3. Call `POST /api/v1/detections/evaluate?window_minutes=15&auth_threshold=3`.
4. Confirm one `AUTH-BRUTE-001` detection, one linked incident and the expected per-user notification for each active admin/analyst.
5. Repeat evaluation and collection. Confirm the same detection/incident is refreshed and duplicates are not created.
6. Acknowledge, investigate and resolve the detection using valid lifecycle transitions. Confirm audit events and notification read scoping.

The CI end-to-end contract test exercises this API chain with a deterministic adapter double. This staging procedure is still required to prove real telemetry flow.

## 6. Prove scheduler and worker recovery

Perform only in staging during an approved test window.

1. Enable the detection schedule as an administrator with the minimum supported interval.
2. Confirm a scheduled run is persisted and visible through `GET /api/v1/detections/runs`.
3. Restart the detection worker while a disposable scheduled run is queued or running:
   ```powershell
   docker compose --env-file .env.production -f compose.production.yaml restart detection-worker
   ```
4. Confirm the worker heartbeat returns, the interrupted run is recovered/retried within its attempt budget, and the run reaches a terminal state.
5. Confirm a stale worker cannot finalize a run after a new owner takes over, and repeated evaluation does not create a duplicate incident.
6. Disable the schedule after the drill. Record run IDs, attempts, timestamps and sanitized logs.

Do not interrupt Redis or kill workers on production to test recovery.

## 7. Scanner safety gates

- **Nuclei:** leave `NUCLEI_ENABLED=false` and `NUCLEI_WORKER_ENABLED=false` unless the host/cloud network policy independently enforces DNS and IP destination restrictions, metadata/private/link-local blocking, DNS-rebinding defenses and the exact authorized target allowlist. Only then run a bounded disposable staging target and a worker lease-loss/restart drill.
- **Shannon:** keep disabled until the bridge is deployed on a dedicated disposable VM and independent reviewers verify VM isolation, DNS/IP allowlists, provider budgets, source mount restrictions, authentication and written target authorization. The current bridge is a single-job reference implementation; it is not a durable production runner.

If these controls are not available, record the engines as explicitly disabled/out of scope with project-owner acceptance. Do not mark their live validation as passed.

## 8. Backup, restore, retention and recovery objectives

Follow [PostgreSQL backup and restore](DATABASE_BACKUP_RESTORE.md):

```powershell
.\ops\backup-postgres.ps1 -EnvFile .env.production
.\ops\verify-postgres-backup.ps1 -BackupPath <backup-archive> -EnvFile .env.production
.\ops\restore-postgres-drill.ps1 -BackupPath <backup-archive> -RestoreEnvFile .env.restore
```

Then verify the restored database's Alembic revision and table count, and perform an application-level read-only smoke test against the isolated restored copy. Separately configure encrypted off-host retention and measure RPO/RTO. Decide and document the Redis backup/recovery strategy; the PostgreSQL scripts do not back up Redis.

## 9. Evidence record

For each row in [the Phase 5 evidence register](PHASE5_STAGING_EVIDENCE.md), record:

| Field | Required value |
|---|---|
| Environment | Non-sensitive staging identifier |
| Operator / timestamp | Operator and UTC timestamp |
| Service version | Exact version/image digest where available |
| Test case | Bounded test identity or action |
| Expected / observed | Counts, states, truncation and result |
| Evidence reference | Restricted sanitized report/log path |
| Outcome | Passed, failed, blocked, skipped or not configured |
| Follow-up | Issue/action owner and due date |

Never store secrets, bearer tokens, authorization headers, raw sensitive event payloads, private hostnames/IPs or unredacted provider responses in the repository.

## Phase 5 exit decision

Phase 5 may be closed only when every required staging check has recorded evidence, failed checks have been fixed and retested, and any disabled/out-of-scope integrations are explicitly accepted by the project owner. CI success is necessary but does not substitute for staging proof.
