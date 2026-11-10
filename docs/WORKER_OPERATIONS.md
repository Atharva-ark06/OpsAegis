# Worker operations

OpsAegis uses separate worker processes for background tasks. The API process should remain responsive and should not host long-running scanner execution.

## Detection worker

The detection worker evaluates persisted findings and scheduled detection work. It uses PostgreSQL for durable records and Redis for queue/lease coordination. Scheduling is disabled by default until an administrator enables it.

## Collection orchestration

The collection orchestration feature supports the explicitly allowlisted Wazuh Manager inventory and Wazuh Indexer alert sources. Manual and scheduled runs share the same bounded adapter paths. Each run records attempts, result counts, truncation state, sanitized error information and timestamps.

Do not infer that every integration has a scheduled collector. CrowdSec, Nuclei and Shannon are not part of the Wazuh collection scheduler.

## Worker health

Check all of the following:
- Process/container state.
- Current heartbeat.
- Redis connectivity and lease ownership.
- Persisted queued/running/failed run records.
- Recent worker logs and retry attempts.

A container can be running while its heartbeat is stale. A heartbeat does not prove a provider endpoint is reachable or that data was ingested.

## Recovery

When a worker is interrupted, inspect the persisted run and lease state before retrying manually. Avoid launching duplicate jobs while an existing lease is active. Follow the application's bounded retry and fencing behavior; do not manually delete queue or database records to make a dashboard look healthy.

## Scanner workers

Nuclei must run in its separate non-root worker with strict external DNS/IP egress controls and resource limits. Shannon runs only through a separately deployed bridge in a disposable authorized staging environment. Neither scanner should run inside the API container.
