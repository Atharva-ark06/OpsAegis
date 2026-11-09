# Isolated Nuclei worker

OpsAegis queues authorized Nuclei assessments in PostgreSQL and delivers job IDs through Redis. The dedicated `nuclei-worker` service runs Nuclei v3.4.10 with the explicitly installed `nuclei-templates` v10.3.1 release and writes normalized findings back to the existing database. The image pins both components; scans pass the template directory explicitly and disable runtime update checks. The API process does not spawn Nuclei.

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

Scan rows are committed before Redis enqueue. The worker also polls durable queued rows, so a transient Redis publish failure does not lose a job. A single renewable Redis lease prevents multiple workers from consuming concurrently. The heartbeat runs independently while a scan is active. If the lease is lost, the worker kills the active Nuclei process, discards uncommitted scan results and leaves the durable row in `running` state for the next lease owner to recover. On startup, interrupted runs are requeued while retry budget remains; execution failures retry up to three attempts with backoff. Scan state and audit records remain in PostgreSQL.

## Validation boundary

CI tests and image builds do not prove live scanner behavior or egress isolation. Keep execution disabled until the host/cloud egress policy, DNS-rebinding protections, staging target authorization and resource limits have been tested. Never scan a target without written authorization.


## Reproducible scanner content

The worker image pins Nuclei CLI v3.4.10 and the public template release v10.3.1. Templates are cloned at image-build time, copied into the non-root runtime image and passed explicitly through `-t /opt/nuclei-templates`. The scan does not fetch or update templates at runtime. To update templates, change the build argument in `backend/Dockerfile.nuclei-worker`, review the upstream release and rebuild the image. A template release update is a security-sensitive code change and must pass CI before deployment.
