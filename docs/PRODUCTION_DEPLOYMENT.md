# Production deployment (Docker Compose)

This is a separate production-oriented stack. Keep `docker-compose.yml` for local development.

## Requirements

- Docker Engine with the Compose v2 plugin.
- A host or VM with persistent storage and enough memory for PostgreSQL, Redis, API, worker and Nginx.
- A DNS name and a TLS-terminating reverse proxy/load balancer in front of the loopback-bound frontend port.
- A backup and restore plan for the PostgreSQL and Redis volumes.

## 1. Prepare production secrets

From the repository root in PowerShell:

```powershell
Copy-Item .env.production.example .env.production
notepad .env.production
```

Replace every `REPLACE_...` value. Generate the application signing key with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Use unique, URL-safe passwords of at least 16 characters for PostgreSQL and Redis. Set the same PostgreSQL password in `POSTGRES_PASSWORD` and the password segment of `DATABASE_URL`. Set the same Redis password in `REDIS_PASSWORD` and `REDIS_URL`. Avoid URL-reserved characters in these passwords unless correctly percent-encoded.

Set `CORS_ORIGINS` to the exact public HTTPS origin, for example `https://soc.example.com`. Never commit `.env.production`; it is covered by the repository's environment-file ignore rules. The checked-in example contains placeholders only.

## 2. Validate and start

```powershell
docker compose --env-file .env.production -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.production.yaml up -d --build
docker compose --env-file .env.production -f compose.production.yaml ps
```

The Compose stack:
- Runs PostgreSQL and password-protected Redis on a private, internal-only data network; neither publishes a host port.
- Runs the API and detection worker as an unprivileged UID with read-only root filesystems, dropped Linux capabilities and no-new-privileges; only bounded temporary filesystems are writable.
- Runs Alembic migrations in a one-shot service before the API and worker start.
- Serves the compiled React application from an unprivileged Nginx container on port 8080, bound to host loopback only.
- Proxies same-origin `/api/` requests to the API and applies baseline browser security headers.
- Uses persistent named volumes for PostgreSQL and Redis and sets container memory/CPU limits.

## 3. TLS and public access

The frontend binds to `127.0.0.1:8080`. Put a maintained TLS reverse proxy or load balancer in front of it and publish only HTTPS to users. Configure that proxy to forward the original host and client/protocol metadata correctly. Do not expose port 8080, 8000, 5432 or 6379 directly to the public internet. The included Nginx container does not terminate public TLS.

## 4. Verify and operate

```powershell
docker compose --env-file .env.production -f compose.production.yaml ps
docker compose --env-file .env.production -f compose.production.yaml logs --tail=100 backend detection-worker frontend migrate
```

The API container health check requires both PostgreSQL and Redis readiness. The migration service must exit successfully before the API and worker are started. The Nginx container exposes a local `/healthz` check.

To stop the stack without deleting data:

```powershell
docker compose --env-file .env.production -f compose.production.yaml down
```

Do not use `down -v` unless you intentionally want to delete the persistent database and Redis volumes. Back up PostgreSQL and test restoration before upgrades.

## Important limitations

- This is a production-oriented container baseline, not a complete managed production service. TLS termination, DNS, firewall rules, host hardening, secret-manager integration, off-host backups, monitoring/alerting, log retention, restore drills and incident runbooks remain operator responsibilities.
- No live production deployment or restore test is claimed by CI.
- Nuclei remains blocked in production because scan execution has not yet moved to an isolated scanner worker. Shannon remains dependent on its separately deployed runner and is disabled by default.
- Use a staging environment and explicit authorization before connecting real security engines or scanning targets.
