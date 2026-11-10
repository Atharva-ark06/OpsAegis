# Database migration workflow

OpsAegis uses Alembic to version PostgreSQL schema changes.

## Local workflow

From the backend directory:

```powershell
alembic current
alembic heads
alembic upgrade head
```

For a disposable local database, inspect the generated SQL before applying a new revision:

```powershell
alembic upgrade head --sql
```

Use the repository's existing migration conventions and ensure each new revision has a clear upgrade path. Downgrades should be implemented where safe and meaningful; do not claim a downgrade is safe if data loss is possible.

## Pull request requirements

- Include the migration in the same PR as the model/API change that requires it.
- Test the full migration chain from an empty disposable database.
- Consider existing production rows, nullability, indexes and table size.
- Avoid long table locks in request-serving deployment windows.
- Do not use production data for migration experiments.
- Document any required operator sequencing or backfill.

## Production

The production Compose topology uses a one-shot migration service before the API and worker start. Review deployment logs and migration state before declaring the release healthy. Back up PostgreSQL before a risky schema change and verify restore procedures independently.

## Important

A successful migration in CI against SQLite is useful preflight evidence, but it does not prove PostgreSQL-specific behavior, production lock duration or rollback safety. Use a PostgreSQL staging environment for those checks.
