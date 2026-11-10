# Troubleshooting

## Frontend loads but API requests fail

- Inspect the browser Network panel for the failing `/api/` request and HTTP status.
- Confirm the frontend is using the same-origin API path.
- Check frontend Nginx logs and confirm `OPS_AEGIS_API_UPSTREAM` points to the private API hostname and correct port.
- Check API logs for authentication, host validation, CORS or upstream errors.
- Do not expose the API publicly as a workaround for a broken private route.

## Login fails

- Confirm the API can reach PostgreSQL and Redis.
- Check whether the account is active and the role is loaded from the database.
- Review rate-limit responses and `Retry-After` before repeatedly retrying.
- Ensure the browser is using the current frontend build and correct origin.
- Do not paste session cookies, tokens or password hashes into an issue.

## Integrations show unavailable or not configured

- Confirm the required variable names and values exist in the API service.
- Check the URL, DNS, firewall and certificate chain from the API runtime network.
- Use a dedicated least-privilege provider account.
- Review sanitized API logs and the integration validation report.
- Do not disable TLS verification to make a connection succeed.

## Collection returns no new records

- Confirm the upstream source contains records in the requested time window.
- Check source permissions and result limits.
- Check whether the source IDs were already ingested and deduplicated.
- Distinguish an empty source response from a failed or skipped request.
- Verify the source timestamp semantics before comparing counts.

## Worker appears online but jobs do not complete

- Check the worker heartbeat and lease ownership.
- Inspect Redis connectivity and queue state.
- Review persisted run attempts, retry count and sanitized error code.
- Check database migrations and worker runtime variables.
- A running container alone is not proof of a functioning worker.

## Railway deployment does not reflect a merge

- Confirm the PR was merged into the branch watched by the service.
- Check that Railway created a deployment for the merge commit SHA.
- Wait for terminal `SUCCESS`; `INITIALIZING` and `BUILDING` are not live.
- Inspect build logs and runtime logs.
- Hard-refresh the browser after successful frontend deployment.

## Docker disk usage is large locally

Use `docker system df -v` to inspect images, containers, volumes and build cache. Pruning unused images/cache is different from deleting volumes. Volumes can contain local PostgreSQL/Redis data. Local Docker cleanup does not delete Railway-managed production data, but it can delete local development data.

For deployment topology see [Railway deployment](RAILWAY_DEPLOYMENT.md) and [production Compose](PRODUCTION_DEPLOYMENT.md).
