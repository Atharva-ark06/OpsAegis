# Operations runbook

## Before a release

- Review the PR diff and confirm the intended base branch.
- Require CI checks relevant to changed components.
- Check database migration compatibility and rollback implications.
- Confirm secrets are configured in the correct service, not committed.
- Review changes to integration scopes, scanner controls and network egress.
- Merge only after review; verify the deployment commit and terminal deployment status.

## After deployment

1. Confirm frontend, API and worker deployments are successful.
2. Check recent startup logs for configuration or migration failures.
3. Open the dashboard and hard-refresh assets.
4. Sign in with a test account appropriate to the changed role.
5. Exercise the specific changed UI/API path.
6. Check API/worker logs for sanitized errors and queue/heartbeat state.
7. Validate any external integration with its documented read-only diagnostic.

## Service health

A live container is not necessarily a healthy worker. For workers, check the application heartbeat and the persisted run state. For integrations, distinguish unconfigured, unavailable, connected and actually ingesting states.

## Incident response

- Preserve relevant logs and source IDs.
- Record the UTC time window and affected service.
- Avoid copying secrets, bearer tokens or raw customer evidence into public issues.
- Rotate exposed credentials at the provider.
- Restore from verified backups only through the documented recovery procedure.

## Backups

PostgreSQL and incident evidence storage must be backed up as a coordinated set when an incident record references an attachment. The existing PostgreSQL runbook covers custom-format backups and a disposable restore drill. Evidence-volume backup and off-host encryption remain operator responsibilities.

## Scanner controls

Keep Nuclei and Shannon disabled until written target authorization, isolated execution, DNS/IP egress restrictions, metadata/private-address blocking and resource limits are independently verified. Never use production targets for Shannon testing.

See [database backup and restore](DATABASE_BACKUP_RESTORE.md), [integration validation](INTEGRATION_VALIDATION.md) and [release readiness](RELEASE_READINESS.md).
