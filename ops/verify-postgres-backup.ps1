[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    [string]$EnvFile = ".env.production"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot "compose.production.yaml"

if (-not [System.IO.Path]::IsPathRooted($BackupPath)) {
    $BackupPath = Join-Path $repoRoot $BackupPath
}
if (-not [System.IO.Path]::IsPathRooted($EnvFile)) {
    $EnvFile = Join-Path $repoRoot $EnvFile
}

if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
    throw "Backup file not found: $BackupPath"
}
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Environment file not found: $EnvFile"
}

$manifestPath = "$BackupPath.manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Backup manifest is missing: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.backup_file -ne [System.IO.Path]::GetFileName($BackupPath)) {
    throw "Manifest backup filename does not match the selected archive."
}
if ($manifest.format -ne "postgresql-custom" -or -not $manifest.archive_listing_verified) {
    throw "Manifest does not identify a verified PostgreSQL custom-format archive."
}

$backupSize = (Get-Item -LiteralPath $BackupPath).Length
$actualHash = (Get-FileHash -LiteralPath $BackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($backupSize -ne [long]$manifest.size_bytes) {
    throw "Backup size does not match its manifest."
}
if ($actualHash -ne [string]$manifest.sha256) {
    throw "SHA-256 mismatch. The backup may be incomplete or modified."
}

& docker compose --env-file $EnvFile -f $composeFile config --quiet
if ($LASTEXITCODE -ne 0) {
    throw "Production Compose configuration validation failed."
}
$containerId = (& docker compose --env-file $EnvFile -f $composeFile ps -q postgres | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
    throw "The production PostgreSQL container is not running; archive verification requires its pg_restore utility."
}

$remoteName = "opsaegis-verify-$([guid]::NewGuid().ToString('N')).dump"
$remotePath = "/tmp/$remoteName"
$copied = $false

try {
    & docker cp $BackupPath "$($containerId):$remotePath"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy the archive into the PostgreSQL container for read-only verification."
    }
    $copied = $true

    $listing = & docker exec $containerId pg_restore --list $remotePath
    if ($LASTEXITCODE -ne 0 -or -not $listing) {
        throw "pg_restore could not read the archive directory."
    }
    $entryCount = @($listing | Where-Object { $_ -match '^\s*\d+;\s+\d+\s+' }).Count
    if ($entryCount -lt 1) {
        throw "The archive listing contains no restorable entries."
    }

    Write-Output "Backup integrity verification passed."
    Write-Output "File: $BackupPath"
    Write-Output "Size (bytes): $((Get-Item -LiteralPath $BackupPath).Length)"
    Write-Output "SHA-256: $actualHash"
    Write-Output "Archive entries: $entryCount"
    Write-Warning "This checks archive readability and integrity only. It does not prove that a full restore or application startup will succeed."
}
finally {
    if ($copied) {
        & docker exec $containerId rm -f $remotePath | Out-Null
    }
}
