# Incident workflow

## Finding triage

Findings can be triaged through the authenticated API using the supported statuses:

- `new`
- `triaged`
- `accepted`
- `false_positive`
- `resolved`

Actual status changes are audit logged. Viewers are read-only; privileged actions require an administrator or analyst role.

## Incident lifecycle

The incident API supports controlled transitions through:

```text
open -> investigating -> contained -> resolved -> closed
```

Controlled returns to earlier active states are supported for specified transitions. Closed incidents are terminal. A non-empty resolution note is required before resolving or closing. Assignees must be active administrators or analysts.

## Investigation timeline

The timeline combines incident audit changes, analyst-authored notes, correlated detections and linked source findings. Entries should retain provenance and timestamps. Notes are bounded and attributed to the author.

## Evidence attachments

Attachments are restricted to authorized roles and supported content types. Upload size and per-incident storage limits are enforced. Files are stored outside the web root; downloads are authorized and integrity-checked. Evidence is sensitive and should be included in encrypted backups.

The JSON evidence export intentionally excludes raw attachment bytes and redacts common secret-like fields. Review exports before external sharing.

## Operational cautions

- Do not use an incident as proof that an upstream source is currently healthy.
- Preserve the original finding and source reference.
- Do not overwrite analyst triage during repeat ingestion.
- Do not treat an approved playbook as an executed response.
- Follow the documented retention process; expired evidence pruning is explicit and dry-run by default.

See [evidence attachment runbook](PHASE6_EVIDENCE_ATTACHMENTS.md), [database backup/restore](DATABASE_BACKUP_RESTORE.md) and [release readiness](RELEASE_READINESS.md).
