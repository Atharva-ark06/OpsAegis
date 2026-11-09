# PostgreSQL backup and restore drill

This runbook covers the PostgreSQL source-of-truth database in the production Compose stack. It creates a PostgreSQL custom-format archive, verifies its SHA-256 and archive directory, and restores a copy into a disposable isolated PostgreSQL container.

The scripts do **not** back up Redis, encrypt archives, upload them off-host, schedule backups, or modify the live database during a restore drill.

## Prerequisites

- PowerShell 7 on the deployment/backup host.
- Docker Engine and Docker Compose v2.
- The production Compose stack running and PostgreSQL healthy for backup/archive verification.
- A protected destination with sufficient free space.
- An approved encrypted storage and off-host transfer process for retaining backup copies.

Never commit backup files, manifests or restore environment files. PostgreSQL archives contain user password hashes, security findings, incident evidence and other sensitive operational data.

## 1. Create a PostgreSQL backup

From the repository root:

```powershell
.\ops\backup-postgres.ps1 -EnvFile .env.production
```

The script:
- validates the production Compose configuration;
- runs `pg_dump --format=custom --no-owner --no-acl` inside the PostgreSQL container;
- reads the database password from the container environment rather than placing it in the command line;
- runs `pg_restore --list` against the generated archive before copying it to the host;
- writes a timestamped `.dump` file and a JSON manifest containing size, UTC creation time and SHA-256;
- uses a restricted Windows ACL for the backup directory when run on Windows.

The default destination is the repository's ignored `backups\` directory. The script does not delete older backups or apply a retention policy.

## 2. Verify a backup archive

Use the exact archive path printed by the backup command:

```powershell
.\ops\verify-postgres-backup.ps1 -BackupPath .\backups\opsaegis-postgres-YYYYMMDDTHHMMSSZ-XXXXXXXX.dump -EnvFile .env.production
```

Verification checks the manifest, recomputes SHA-256, copies the archive temporarily into the running PostgreSQL container and asks `pg_restore --list` to parse its directory. The temporary container-side copy is removed afterward.

This verifies file integrity and archive readability; it is **not** a full restore test.

## 3. Prepare a dedicated restore environment

Create a separate file at the repository root named `.env.restore`. It must contain exactly these three entries (use a new password, not the production password):

```dotenv
POSTGRES_DB=opsaegis_restore
POSTGRES_USER=opsaegis_restore
POSTGRES_PASSWORD=REPLACE_WITH_A_UNIQUE_RANDOM_PASSWORD
```

Generate a password locally if needed:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Keep `.env.restore` private. On Windows, restrict its ACL to your account and SYSTEM (for example, use `icacls .env.restore /inheritance:r /grant:r "<your-account>:R" "SYSTEM:F"`). The restore script rejects additional variables so production application credentials cannot accidentally be passed into the drill container.

## 4. Run an isolated restore drill

```powershell
.\ops\restore-postgres-drill.ps1 -BackupPath .\backups\opsaegis-postgres-YYYYMMDDTHHMMSSZ-XXXXXXXX.dump -RestoreEnvFile .env.restore
```

The script:
- verifies the manifest and SHA-256 before starting;
- starts a disposable `postgres:16-alpine` container with `--network none` and no published ports;
- restores the custom archive into the fresh database with `pg_restore --exit-on-error`;
- checks that the Alembic version table exists and that public tables were restored;
- removes the temporary container even when a restore or check fails.

Use `-KeepContainer` only when you explicitly need to inspect the isolated restored database. If retained, remove it manually after inspection:

```powershell
docker rm -f <container-name-printed-by-script>
```

This drill does not connect the restored database to the API or workers. Application-level staging validation is a separate step.

## 5. Operational requirements not automated here

- Encrypt backup archives before they leave the protected host; use approved encrypted storage and transport. The archive and manifest produced by these scripts are not encrypted.
- Copy backups off-host and keep access restricted. A backup stored only on the same host or volume is not disaster recovery.
- Define and test retention, rotation, monitoring, backup-failure alerts, RPO and RTO.
- Back up Redis separately if the deployment's recovery objectives require preserving queue/cache state; this PostgreSQL workflow does not include Redis.
- Perform periodic full restore drills and record the backup timestamp, archive hash, Alembic revision, restore duration and operator.
- Before a production upgrade, take and verify a backup. Never point the restore-drill script at a live production database: it intentionally restores only into its own disposable isolated container.
- Do not use `docker compose down -v` as a backup or restore procedure; it deletes named volumes.

A successful script run is evidence of a PostgreSQL archive and an isolated restore at that point in time. It does not establish off-host recoverability, encrypted retention, application compatibility, or production disaster-recovery readiness.
