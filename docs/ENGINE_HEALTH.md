# Engine health indicators

OpsAegis reports integration health from backend endpoints. The frontend does not infer a healthy engine from a configured URL, a saved target, or a previous scan.

## Health endpoints and permissions

| Engine | Endpoint | What it checks |
| --- | --- | --- |
| Nuclei | `GET /api/v1/integrations/nuclei/health` | Nuclei is enabled and the isolated worker has a current Redis heartbeat. The scanner executable and pinned templates are packaged in the separate worker image. |
| Shannon | `GET /api/v1/integrations/shannon/health` | The external runner bridge is configured and its authenticated HTTPS health check identifies a healthy Shannon engine. |

Both endpoints require an authenticated administrator or analyst. Viewer accounts do not call them; their cards show **Restricted** instead of reporting a misleading connection failure.

## Status meanings

- **Healthy** — the backend health endpoint returned healthy and execution is enabled.
- **Unhealthy** — the integration is configured, but its health check failed.
- **Not configured** — required settings or runtime prerequisites are missing.
- **Execution disabled** — the backend reports configuration but does not report execution as enabled.
- **Unknown** — the health request failed or returned no usable result. Refresh to retry.
- **Restricted** — the current role is not authorized to retrieve the health details.

The UI fails closed: an inconsistent response cannot be shown as healthy unless the backend reports a healthy status, configuration, and enabled execution.

## Troubleshooting

### Nuclei shows Not configured

1. Confirm `NUCLEI_ENABLED=true` in the backend environment.
2. Confirm the configured Nuclei binary is installed and available to the backend process.
3. Restart the backend after changing environment variables.
4. Call the Nuclei health endpoint with an administrator or analyst token and inspect its response.

Nuclei still executes in the API runtime in the current architecture. Keep it disabled in production until the dedicated isolated scanner worker and egress/resource controls are deployed.

### Shannon shows Not configured or Unhealthy

1. Confirm `SHANNON_ENABLED=true`.
2. Confirm the external runner URL uses HTTPS and the runner token is configured server-side.
3. Confirm the runner is reachable from the OpsAegis backend and its authenticated `/v1/health` response reports `status=healthy` and `engine=shannon`.
4. Do not expose the runner token to the frontend or commit it to the repository.

The Shannon runner is a separate deployment; OpsAegis does not bundle or claim to have live-validated it.

## Important distinction

Health is a connectivity/configuration signal, not a scan result. A healthy card does not prove that any target has been scanned, that findings exist, or that telemetry is flowing. Verify scan history and ingested source findings separately. Dashboard refresh rechecks health but does not start scans or collect findings.


## Background worker health

The production Compose stack checks the detection-worker and opt-in Nuclei-worker containers against their Redis heartbeat keys. A running container is not considered healthy if its heartbeat has expired. The detection worker uses per-run fencing tokens so an old lease owner cannot finalize a scheduled run after a new worker has reclaimed it. See [Production Deployment](PRODUCTION_DEPLOYMENT.md#worker-lease-and-restart-recovery) for staging recovery checks.

Container health is an operational signal, not proof that detection schedules are enabled, that source telemetry is arriving, or that a scan has succeeded.
