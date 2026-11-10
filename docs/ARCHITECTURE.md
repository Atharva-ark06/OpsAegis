# System architecture

## Service responsibilities

| Component | Responsibility | Must not do |
|---|---|---|
| React frontend | Authenticated operator interface; sends same-origin API requests | Connect directly to PostgreSQL/Redis or hold provider secrets |
| FastAPI API | Authentication, authorization, validation, integrations, persistence and audit events | Run long-lived scans inside the web process |
| PostgreSQL | Durable application records, findings, incidents, schedules and evidence metadata | Be exposed directly to browsers or public networks |
| Redis | Queue coordination, cache, rate limits and worker leases | Be treated as the durable system of record |
| Detection worker | Evaluates persisted findings and processes scheduled detection work | Collect arbitrary external telemetry or launch scanners |
| Collection/scanner/runner processes | Execute only their specifically assigned, bounded jobs | Receive unrelated secrets or unrestricted network access |

## Request path

The hosted frontend serves the compiled application through unprivileged Nginx. Requests under `/api/` are reverse-proxied to the private API service. This keeps browser traffic on one public origin and avoids publishing the API, database or Redis as browser-facing services.

The API validates the authenticated user and role before performing an operation. Integration adapters run server-side and use backend-only credentials. Results are normalized with source provenance before persistence.

## Data services

PostgreSQL stores durable application state. Redis supports coordination and bounded ephemeral state such as queues, cache entries, rate-limit counters and worker leases. The detection worker uses both services. A Redis heartbeat is operational evidence about a worker process, not proof that an external data source is healthy.

## Trust boundaries

1. **Browser boundary:** only public frontend assets and session-scoped API traffic cross this boundary.
2. **API boundary:** provider credentials remain server-side; user role and input validation are enforced here.
3. **Data boundary:** PostgreSQL and Redis remain private service dependencies.
4. **Execution boundary:** Nuclei and Shannon require isolated execution environments, target authorization and independent egress restrictions.
5. **Evidence boundary:** uploaded incident evidence is sensitive, stored outside the web root and served through authorized endpoints.

## Deployment variants

- Railway: separate frontend, API and detection-worker services with managed PostgreSQL and Redis.
- Self-managed host: `compose.production.yaml`, persistent volumes and an external TLS-terminating reverse proxy.
- Local development: `docker-compose.yml` for local dependencies and separate development servers.

The deployment variants share application code but are not interchangeable operational recipes. See [Railway deployment](RAILWAY_DEPLOYMENT.md) and [production Compose deployment](PRODUCTION_DEPLOYMENT.md).
