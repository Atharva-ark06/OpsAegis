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
$actualHash = (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($manifest.backup_file -ne [System.IO.Path]::GetFileName($BackupPath) -or
    $manifest.format -ne "postgresql-custom" -or
    -not $manifest.archive_listing_verified -or
    $actualHash -ne [string]$manifest.sha256) {
    throw "Backup manifest or SHA-256 verification failed. Restore was not started."
}

# Validate required variable names without displaying or logging their values.
$envText = Get-Content -LiteralPath $RestoreEnvFile -Raw
foreach ($requiredName in @("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")) {
    if ($envText -notmatch "(?m)^\s*$requiredName\s*=") {
        throw "Restore environment file must define $requiredName."
    }
}

$containerName = "opsaegis-restore-drill-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$remotePath = "/tmp/opsaegis-restore.dump"
$containerCreated = $false

try {
    # No port publishing and --network none keep this temporary database isolated.
    & docker run --detach --name $containerName --network none --env-file $RestoreEnvFile postgres:16-alpine
    if ($LASTEXITCODE -ne 0) {
        throw "Could not start the isolated PostgreSQL restore container."
    }
    $containerCreated = $true

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $containerName pg_isready -U postgres | Out-Null
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
PGPASSWORD="$POSTGRES_PASSWORD" pg_restore --exit-on-error --no-owner --no-acl --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" /tmp/opsaegis-restore.dump
migration="$(PGPASSWORD="$POSTGRES_PASSWORD" psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --command='SELECT version_num FROM alembic_version')"
tables="$(PGPASSWORD="$POSTGRES_PASSWORD" psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --command="SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
test -n "$migration"
test "$tables" -gt 0
printf 'Alembic revision: %s\nPublic tables restored: %s\n' "$migration" "$tables"
'@
    $result = & docker exec $containerName sh -ec $restoreScript
    if ($LASTEXITCODE -ne 0) {
        throw "Restore or post-restore schema checks failed."
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
    if ($containerCreated -and -not $KeepContainer) {
        & docker rm --force $containerName | Out-Null
    }
}
