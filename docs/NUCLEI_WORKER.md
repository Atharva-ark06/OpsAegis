# Isolated Nuclei worker

OpsAegis queues authorized Nuclei assessments in PostgreSQL and delivers job IDs through Redis. The dedicated `nuclei-worker` service runs the pinned Nuclei CLI and writes normalized findings back to the existing database. The API process does not spawn Nuclei.

## Disabled-by-default deployment

The worker is behind the Compose `scanner` profile and both `NUCLEI_ENABLED` and `NUCLEI_WORKER_ENABLED` default to false. Do not enable either flag until all deployment controls below are independently verified.

Build and validate the production stack:

```powershell
docker compose --env-file .env.production -f compose.production.yaml --profile scanner build nuclei-worker
docker compose --env-file .env.production -f compose.production.yaml config --quiet
```

## Required network controls

The scanner requires outbound HTTPS to the explicitly authorized target. The Compose `scanner-egress` network is not an allowlist. Before enabling scans, enforce outbound DNS and IP restrictions at the host/cloud firewall or an egress proxy so the worker can reach only approved target origins and required DNS infrastructure. Block private, loopback, link-local, multicast, reserved and cloud-metadata ranges at the network layer as well as in application validation. Defend against DNS rebinding and redirects to disallowed destinations. Verify the policy from inside the deployed worker.

## Container controls

The worker runs as UID 10002, with a read-only root filesystem, a bounded tmpfs, all Linux capabilities dropped, no-new-privileges, PID limit, CPU limit and memory limit. Do not mount the Docker socket, host paths, or secrets unrelated to the scan worker. Keep the scanner on a dedicated host or isolated environment for production use.

## Queue and recovery

Scan rows are committed before Redis enqueue. The worker also polls durable queued rows, so a transient Redis publish failure does not lose a job. A single renewable Redis lease prevents multiple workers from consuming concurrently. On startup, interrupted runs are requeued while retry budget remains; execution failures retry up to three attempts with backoff. Scan state and audit records remain in PostgreSQL.

## Validation boundary

CI tests and image builds do not prove live scanner behavior or egress isolation. Keep execution disabled until the host/cloud egress policy, DNS-rebinding protections, staging target authorization and resource limits have been tested. Never scan a target without written authorization.
