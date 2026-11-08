# Security Baseline

## Production startup requirements
- Set `OPS_AEGIS_ENV=production`; startup rejects the development JWT secret and weak/placeholder signing keys.
- Use PostgreSQL with a unique database password of at least 16 characters; SQLite is development/test only.
- Use a reachable non-loopback Redis URL.
- Set explicit HTTPS CORS origins only. Wildcards, HTTP origins, loopback hosts and URL paths are rejected.
- Keep Nuclei disabled in production until execution is moved from the API runtime to a dedicated unprivileged scanner worker with egress and resource controls.
- Generate and store secrets outside Git. The checked-in `.env.example` is development-only and contains deliberately insecure local defaults.
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
