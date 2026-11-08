# Security Baseline

## Production startup requirements
- Set `OPS_AEGIS_ENV=production`; startup rejects the development JWT secret and weak/placeholder signing keys.
- Use PostgreSQL with a unique database password of at least 16 characters; SQLite is development/test only.
- Use a reachable non-loopback Redis URL with a unique password of at least 16 characters embedded in the URL. Use `rediss://` when Redis traffic crosses an untrusted network; the production Compose network is private and internal.
- Set explicit HTTPS CORS origins only. Wildcards, HTTP origins, loopback hosts and URL paths are rejected.
- Keep Nuclei disabled in production until execution is moved from the API runtime to a dedicated unprivileged scanner worker with egress and resource controls.
- Generate and store secrets outside Git. Production startup rejects obvious placeholders and low-diversity JWT signing keys, requires authenticated Redis, and rejects loopback PostgreSQL/Redis hosts. The checked-in `.env.example` is development-only and contains deliberately insecure local defaults.
- The production migration and detection-worker containers receive only the JWT signing key, database URL, Redis URL and required runtime settings. The API container alone receives the integration API credentials from `.env.production`.
- These startup checks do not replace TLS termination, firewall policy, secret management, backup/restore testing, monitoring or deployment review.


- Never commit .env files, credentials, tokens, private keys or customer evidence.
- Replace development credentials before use outside a local workstation.
- Development ports are bound to loopback by default.
- Disable interactive API documentation in production.
- Never expose engine credentials to frontend code.
- Run Nuclei and Shannon only against explicitly authorized targets.
- Isolate scan workers and apply network egress restrictions, timeouts and resource quotas.
- Restrict Shannon to owned lab/staging environments in the initial release.
- Require authorization and audit logging for disruptive actions such as blocking.
- Use least-privilege service credentials for each integration.

- Shannon is a separate AGPL-3.0 program; review license obligations before redistribution or network-service deployment.
- Never run Shannon in the FastAPI process or expose the OpsAegis host Docker socket to the API.
- Use a separately isolated, unprivileged Shannon runner with a dedicated token, read-only source checkout, target allowlists, DNS-rebinding defenses, strict egress controls and resource/cost quotas.
- Keep Shannon disabled until its external bridge passes an authenticated HTTPS health check.
- Ingest only runner findings explicitly marked exploited with non-empty proof; never treat incomplete scans as clean results.


## Production credential scope
- Keep `.env.production` out of version control; `.gitignore` excludes `.env.*` except the checked-in example templates.
- Use the same generated URL-safe PostgreSQL password in `POSTGRES_PASSWORD` and the password component of `DATABASE_URL`.
- Use the same generated URL-safe Redis password in `REDIS_PASSWORD` and the password component of `REDIS_URL`.
- Replace every `CHANGE_ME` placeholder. The application rejects these placeholder values at production startup.
- The migration and detection-worker services do not need Wazuh, CrowdSec, VirusTotal, AbuseIPDB, NVD, Nuclei or Shannon credentials; Compose intentionally does not pass the full production environment file to those services.
- Treat the environment template as a shape/example only. It contains placeholders and must not be used as a live deployment configuration.
