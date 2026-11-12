# Railway deployment notes

This guide describes the current OpsAegis Railway project topology. It is not a replacement for the Railway dashboard's live deployment status; check service deployments before relying on a release.

## Services

| Service | Repository root | Build/runtime |
|---|---|---|
| Frontend | `/frontend` | `frontend/Dockerfile.production` |
| API | `/backend` | `backend/Dockerfile.production` |
| Detection worker | `/backend` | `backend/Dockerfile.production`, start command `python -m app.worker` |
| Kali terminal | `/runner/kali-terminal` | `runner/kali-terminal/Dockerfile`, private ttyd service |
| PostgreSQL | Managed Railway service | Persistent database |
| Redis | Managed Railway service | Queue/cache/coordination |

The hosted dashboard URL is https://frontend-production-cdff.up.railway.app/.

## Intended request and dependency paths

```text
Browser
  |
  | HTTPS
  v
Public frontend domain
  |
  | Nginx /api/* reverse proxy
  v
Private API service (backend:8000)
  |                    |
  v                    v
PostgreSQL            Redis
                       ^
                       |
                 Detection worker
```

The frontend uses same-origin `/api/` requests. Its Nginx configuration proxies those requests to the private API hostname. The API and worker use private PostgreSQL and Redis connection URLs. The browser must never connect directly to the database or Redis.

## Deployment workflow

1. Merge reviewed changes into the branch configured as the Railway source branch (currently `main`).
2. Confirm Railway created a deployment for the expected merge commit.
3. Wait for the deployment to reach `SUCCESS`; a queued or building deployment is not live yet.
4. Check the service's current state and recent logs.
5. Open the public frontend and hard-refresh the browser.
6. Verify the relevant UI path and authenticated API behavior. A successful frontend build alone does not validate upstream integrations.

A frontend-only change normally requires a frontend deployment. API or worker changes require their corresponding services to deploy. Shared backend changes may affect both API and worker images.

## Private networking and the Railway canvas

The Railway canvas is a visualization, not a complete packet-level network trace. An absent diagram edge does not prove that two services cannot communicate. Verify the configured private hostnames, service variables, proxy configuration and runtime logs instead.

For the current frontend path, inspect `frontend/Dockerfile.production` and `frontend/nginx.production.conf`. The default upstream is `backend:8000`, and `/api/` is proxied to that upstream. Keep API, PostgreSQL and Redis private; do not add public domains merely to make the canvas look connected.

## Secrets

Set integration credentials in the API service only unless a specific worker explicitly needs them. Never put provider credentials in `VITE_*` variables. Use Railway's variable UI or an approved secret manager; do not commit values to Git or paste them into issues.

## Troubleshooting checklist

- Confirm the service is watching the intended branch and root directory.
- Confirm the Dockerfile path and build context match the service root.
- Confirm the latest deployment commit equals the intended merge commit.
- Inspect build logs before investigating runtime behavior.
- Inspect runtime logs for startup errors, missing variables and private DNS/connection failures.
- Confirm API and worker have the required database/Redis variables.
- Confirm frontend Nginx upstream points to the API's private hostname and correct port.
- Validate the public frontend after deployment; do not assume a successful build means the UI feature works.

For local production Compose deployment, see [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md).


## Kali team terminal

The Kali terminal is a separate service in the same production environment. It must use root directory `/runner/kali-terminal`, private endpoint `kali-terminal`, `PORT=7681`, and a persistent volume mounted at `/workspace`. Do not create a public Railway domain or TCP proxy for it.

The frontend exposes only the same-origin `/terminal/` path. Nginx performs an API `auth_request` for every terminal page request and WebSocket handshake. The API issues a five-minute HttpOnly, Secure-in-production, SameSite=Strict cookie only to active administrators and analysts; it rechecks the current database role and account status. Viewers are denied. The API service uses `KALI_TERMINAL_ENABLED=true` and `KALI_TERMINAL_URL=http://kali-terminal.railway.internal:7681` after the terminal service is deployed and reachable.

The shell runs as an unprivileged Linux user. The team shares the container and persistent `/workspace` directory; do not treat it as per-user filesystem isolation. The terminal is for authorized lab, CTF and administrative use only. Its availability does not grant permission to scan arbitrary targets or bypass the separate Nuclei/Shannon authorization workflows.
