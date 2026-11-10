# Phase 6.2 — incident evidence attachment operations

## Scope and security boundary

The attachment API stores bounded evidence files associated with one incident. It is separate from the redacted JSON timeline export. Files are not served from the frontend web root and are not embedded in incident API responses.

Only active administrators and analysts may list, upload or download attachments. Viewers remain unable to access the attachment endpoints. The API:
- accepts PDF, PNG, JPEG and UTF-8 text after inspecting file bytes; it does not trust the browser-supplied MIME type;
- enforces a configurable per-file byte limit (10 MiB default; configuration is capped at 25 MiB);
- limits each incident to 100 unexpired attachments and a configurable aggregate byte quota (100 MiB default; 500 MiB hard ceiling);
- generates opaque storage keys and never uses a supplied filename as a path;
- writes a temporary file then atomically moves it into the private evidence directory;
- records uploader, original display filename, detected media type, size, SHA-256 digest, creation time and expiry;
- verifies the stored file digest before download and forces attachment disposition, `no-store` and `nosniff`;
- audits uploads and downloads without recording file contents.

The digest detects accidental or unauthorized content changes relative to the database metadata. It is not a signed, append-only or independently tamper-proof chain of custody. The implementation does not scan files for malware, encrypt files itself, provide tenant isolation, or offer immutable/WORM storage. Operators must protect the host volume and backups.

## Configuration

Backend settings:

| Setting | Default | Bound |
|---|---:|---|
| `EVIDENCE_STORAGE_PATH` | `./.data/evidence` | Operator-managed filesystem path |
| `EVIDENCE_MAX_ATTACHMENT_BYTES` | `10485760` (10 MiB) | 1 byte–25 MiB |
| `EVIDENCE_MAX_INCIDENT_BYTES` | `104857600` (100 MiB) | 1 MiB–500 MiB |
| `EVIDENCE_RETENTION_DAYS` | `365` | 1–3650 days |

Local and production Compose mount a named `evidence_data` volume at `/var/lib/opsaegis/evidence`. The production API container runs unprivileged; the image prepares the mount point for UID 10001. The production reverse proxy allows an 11 MiB request body to accommodate multipart overhead around the default 10 MiB file limit. If the configured file limit is increased, update the reverse-proxy limit deliberately and keep it no higher than the application hard ceiling plus multipart overhead.

Do not mount the evidence volume into the frontend, scanner workers or unrelated services. Restrict host access and use encrypted storage where required by policy.

## API

- `POST /api/v1/incidents/{id}/attachments` — multipart form field `file`; admin/analyst.
- `GET /api/v1/incidents/{id}/attachments` — metadata for up to 100 active attachments; admin/analyst.
- `GET /api/v1/incidents/{id}/attachments/{attachment_id}` — integrity-checked download; admin/analyst.

The original filename is display metadata only. The server chooses the storage key. Downloads use a generic binary content type and attachment disposition to avoid rendering uploaded content in the browser. Expired attachments are hidden and cannot be downloaded.

## Retention procedure

Pruning is deliberately operator-triggered; no background job deletes evidence automatically.

From the repository root:

```powershell
# Inspect the number of expired records; no changes are made.
docker compose -f compose.production.yaml exec backend python -m scripts.purge_expired_evidence

# Permanently delete expired files and their metadata after approval.
docker compose -f compose.production.yaml exec backend python -m scripts.purge_expired_evidence --apply
```

The command processes at most 500 records by default (maximum 5,000 per invocation), validates generated storage keys, and records a minimized audit summary. Run the dry-run first and retain the command output with the approved retention record. A skipped file is reported and causes a non-zero result; investigate it rather than weakening the path checks.

## Backup and restore

The evidence volume contains the binary files; PostgreSQL contains the metadata and SHA-256 digests. Back up both under the same retention and access-control policy. A database-only restore is incomplete because attachment metadata may point to absent files. A volume-only restore is incomplete because the database metadata is required to authorize and verify each file.

After restoring both into an isolated environment:
1. verify the database migration is at the expected revision;
2. verify a representative attachment is present and downloads for an authorized analyst;
3. confirm the response digest matches the metadata and a deliberately altered test copy fails integrity verification;
4. confirm expired files are not downloadable;
5. retain sanitized evidence without filenames, incident content, file bytes or internal host paths.

The existing PostgreSQL backup scripts do not back up the evidence volume. Configure encrypted off-host copies and test their restore separately. Do not claim RPO/RTO until measured.

## Staging acceptance

Use only an authorized disposable staging incident and synthetic test files. Verify:
- analyst/admin upload, list and download succeed;
- viewer access is denied;
- unsupported, empty and oversized files are rejected;
- path-like filenames cannot affect storage paths;
- the SHA-256 header matches the file and metadata;
- a modified stored file fails closed;
- expired evidence is hidden and rejected, then removed only after an approved `--apply` run;
- both database metadata and the evidence volume survive the approved backup/restore drill;
- audit records contain metadata only and no file bytes or credentials.

No staging evidence is claimed by the repository implementation or its automated tests. Record the actual environment, commit, test results and independent reviewer in the Phase 6 evidence register.
