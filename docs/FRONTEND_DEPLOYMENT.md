# Frontend production deployment

## Build and runtime stages

The production frontend Dockerfile uses a Node build stage to install locked dependencies and compile the Vite application. The resulting static assets are served by an unprivileged Nginx runtime image.

The runtime listens on port 8080. The frontend image sets the API upstream to the private API service and loads the Nginx template at container startup.

## API routing

The browser calls the same-origin `/api/` path. Nginx forwards those requests to the configured private API upstream. This keeps API credentials and internal service hostnames out of the browser bundle.

Do not set a public API URL in `VITE_API_BASE_URL` for the production deployment unless the architecture is intentionally changed and reviewed. Do not expose PostgreSQL or Redis to support frontend access.

## Cache and UI verification

After a successful frontend deployment:
1. Confirm the deployment commit SHA matches the merge commit.
2. Open the production dashboard.
3. Hard-refresh with Ctrl+Shift+R to bypass cached assets.
4. Inspect the browser Network panel for the new asset hashes and API response statuses.
5. Verify the changed control's loading, disabled, error and success behavior.

A successful Docker build does not prove that the private API route or authenticated feature works.

## Railway

The Railway frontend service uses the repository's `/frontend` root and `Dockerfile.production`. See [Railway deployment notes](RAILWAY_DEPLOYMENT.md) for the full service topology.
