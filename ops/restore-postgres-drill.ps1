[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    [string]$RestoreEnvFile = ".env.restore",
    [switch]$KeepContainer
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not [System.IO.Path]::IsPathRooted($BackupPath)) {
    $BackupPath = Join-Path $repoRoot $BackupPath
}
if (-not [System.IO.Path]::IsPathRooted($RestoreEnvFile)) {
    $RestoreEnvFile = Join-Path $repoRoot $RestoreEnvFile
}

if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
    throw "Backup file not found: $BackupPath"
}
if (-not (Test-Path -LiteralPath $RestoreEnvFile -PathType Leaf)) {
    throw "Restore environment file not found: $RestoreEnvFile"
}

$manifestPath = "$BackupPath.manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Backup manifest is missing: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$backupSize = (Get-Item -LiteralPath $BackupPath).Length
$actualHash = (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($backupSize -ne [long]$manifest.size_bytes -or
    $manifest.backup_file -ne [System.IO.Path]::GetFileName($BackupPath) -or
    $manifest.format -ne "postgresql-custom" -or
    -not $manifest.archive_listing_verified -or
    $actualHash -ne [string]$manifest.sha256) {
    throw "Backup manifest or SHA-256 verification failed. Restore was not started."
}

# Validate required variable names without displaying or logging their values.
$definedValues = @{}
foreach ($line in Get-Content -LiteralPath $RestoreEnvFile) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) {
        continue
    }
    $parts = $trimmed -split "=", 2
    if ($parts.Count -ne 2 -or $parts[0].Trim() -notin @("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")) {
        throw "Use a dedicated restore env file containing only POSTGRES_DB, POSTGRES_USER and POSTGRES_PASSWORD."
    }
    $definedValues[$parts[0].Trim()] = $parts[1].Trim()
}
foreach ($requiredName in @("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")) {
    if (-not $definedValues.ContainsKey($requiredName) -or [string]::IsNullOrWhiteSpace($definedValues[$requiredName])) {
        throw "Restore environment file must define a non-empty $requiredName."
    }
}

$containerName = "opsaegis-restore-drill-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$remotePath = "/tmp/opsaegis-restore.dump"
$containerCreated = $false
$restoreCheckPath = $null

try {
    # No port publishing and --network none keep this temporary database isolated.
    & docker run --detach --name $containerName --network none --env-file $RestoreEnvFile postgres:16-alpine
    if ($LASTEXITCODE -ne 0) {
        throw "Could not start the isolated PostgreSQL restore container."
    }
    $containerCreated = $true

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $containerName pg_isready | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) {
        throw "The isolated PostgreSQL container did not become ready."
    }

    & docker cp $BackupPath "$($containerName):$remotePath"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy the verified backup into the isolated restore container."
    }

    $restoreScript = @'
set -eu
export PGPASSWORD="$POSTGRES_PASSWORD"

pg_restore --exit-on-error --no-owner --no-acl \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB" \
  /tmp/opsaegis-restore.dump

migration="$(psql --no-psqlrc --tuples-only --no-align \
  -v ON_ERROR_STOP=1 \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB" \
  --command='SELECT version_num FROM alembic_version')"

tables="$(psql --no-psqlrc --tuples-only --no-align \
  -v ON_ERROR_STOP=1 \
  --username="$POSTGRES_USER" \
  --dbname="$POSTGRES_DB" \
  --command="SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"

test -n "$migration"
test "$tables" -gt 0

printf 'Alembic revision: %s\\nPublic tables restored: %s\n' "$migration" "$tables"
'@

    $restoreCheckPath = Join-Path $env:TEMP "$containerName-restore-check.sh"
    [System.IO.File]::WriteAllText(
        $restoreCheckPath,
        $restoreScript,
        [System.Text.Encoding]::ASCII
    )

    & docker cp $restoreCheckPath "$($containerName):/tmp/restore-check.sh"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy the restore verification script."
    }

    $result = & docker exec $containerName sh /tmp/restore-check.sh
    $restoreExitCode = $LASTEXITCODE

    if ($restoreExitCode -ne 0) {
        throw "Restore or post-restore schema checks failed. Exit code: $restoreExitCode"
    }

    Write-Output "Isolated PostgreSQL restore drill passed."
    Write-Output $result
    Write-Output "Temporary container: $containerName"
    if ($KeepContainer) {
        Write-Warning "The isolated container was retained by request. Remove it when finished: docker rm -f $containerName"
    }
    else {
        Write-Output "The temporary database will be removed after this script exits."
    }
}
finally {
    if ($restoreCheckPath -and (Test-Path -LiteralPath $restoreCheckPath)) {
        Remove-Item -LiteralPath $restoreCheckPath -Force -ErrorAction SilentlyContinue
    }

    if ($containerCreated -and -not $KeepContainer) {
        & docker rm --force $containerName | Out-Null
    }
}
