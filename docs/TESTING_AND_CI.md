# Testing and CI

## Local backend checks

```powershell
cd backend
pip install -r requirements.txt
pytest -q
```

For migration validation, point `DATABASE_URL` at a disposable database and run:

```powershell
alembic upgrade head
```

Do not run migration experiments against production data.

## Local frontend checks

```powershell
cd frontend
npm ci
npm test
npm run build
```

## Production configuration preflight

The repository includes production Compose validation and a CI preflight that imports the API, validates settings/migrations and checks the production Compose configuration. Follow the commands in the README and [production deployment guide](PRODUCTION_DEPLOYMENT.md).

## Security automation

The security workflow includes full-history secret scanning and dependency vulnerability audits for the declared Python dependency sets. Review [security scanning in CI](SECURITY_SCANNING.md) for scope and limitations.

## Interpreting CI

A green workflow means the checks that ran passed on that commit. It does not prove:
- external provider credentials are valid;
- production network paths are reachable;
- telemetry is arriving or complete;
- scanner egress restrictions are enforced;
- backups can be restored;
- production host hardening is complete.

Use [live integration validation](INTEGRATION_VALIDATION.md) and [release readiness](RELEASE_READINESS.md) for operational acceptance evidence.
