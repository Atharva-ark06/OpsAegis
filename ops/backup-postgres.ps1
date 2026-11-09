[CmdletBinding()]
param(
    [string]$EnvFile = ".env.production",
    [string]$OutputDirectory = "backups"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot "compose.production.yaml"

if (-not [System.IO.Path]::IsPathRooted($EnvFile)) {
    $EnvFile = Join-Path $repoRoot $EnvFile
}
if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot $OutputDirectory
}

if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Environment file not found: $EnvFile"
}
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "Production Compose file not found: $composeFile"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

# Backups contain user credentials, findings and incident evidence. On Windows,
# restrict this newly-created backup directory to the current user and SYSTEM.
if ($IsWindows) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $OutputDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not restrict backup-directory permissions."
    }
}

function Invoke-ComposeCapture {
    param([string[]]$ComposeArguments)
    $output = & docker compose --env-file $EnvFile -f $composeFile @ComposeArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose command failed: $($ComposeArguments -join ' ')"
    }
    return ($output | Out-String).Trim()
}

# Validate the selected Compose/environment pair before touching the database.
& docker compose --env-file $EnvFile -f $composeFile config --quiet
if ($LASTEXITCODE -ne 0) {
    throw "Production Compose configuration validation failed."
}

$containerId = Invoke-ComposeCapture -ComposeArguments @("ps", "-q", "postgres")
if ([string]::IsNullOrWhiteSpace($containerId)) {
    throw "The production PostgreSQL container is not running."
}

$timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$fileName = "opsaegis-postgres-$timestamp.dump"
$remotePath = "/tmp/$fileName"
$finalPath = Join-Path $OutputDirectory $fileName
$tempPath = "$finalPath.partial"
$remoteCreated = $false

try {
    # Run pg_dump inside the database container. The password is read from the
    # container environment; it is never placed in the command line or report.
    $dumpScript = @'
set -eu
umask 077
file="/tmp/$1"
PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-acl --username="$POSTGRES_USER" --file="$file" "$POSTGRES_DB"
pg_restore --list "$file" >/dev/null
printf "archive_created_and_listed\n"
'@
    & docker compose --env-file $EnvFile -f $composeFile exec -T postgres sh -ec $dumpScript sh $fileName
    if ($LASTEXITCODE -ne 0) {
        throw "pg_dump or the in-container archive listing check failed."
    }
    $remoteCreated = $true

    & docker cp "$($containerId):$remotePath" $tempPath
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy the PostgreSQL archive from the database container."
    }

    $fileInfo = Get-Item -LiteralPath $tempPath
    if ($fileInfo.Length -le 0) {
        throw "The generated PostgreSQL archive is empty."
    }

    $hash = (Get-FileHash -LiteralPath $tempPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Move-Item -LiteralPath $tempPath -Destination $finalPath

    $manifest = [ordered]@{
        format = "postgresql-custom"
        backup_file = $fileName
        created_at_utc = [DateTime]::UtcNow.ToString("o")
        size_bytes = (Get-Item -LiteralPath $finalPath).Length
        sha256 = $hash
        archive_listing_verified = $true
        dump_options = @("--format=custom", "--no-owner", "--no-acl")
    }
    $manifestPath = "$finalPath.manifest.json"
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    Write-Output "PostgreSQL backup created: $finalPath"
    Write-Output "Size (bytes): $($manifest.size_bytes)"
    Write-Output "SHA-256: $hash"
    Write-Output "Manifest: $manifestPath"
    Write-Warning "The archive is not encrypted by this script. Store it only on encrypted storage and transfer it through an approved secure channel."
}
finally {
    if (Test-Path -LiteralPath $tempPath) {
        Remove-Item -LiteralPath $tempPath -Force
    }
    if ($remoteCreated) {
        & docker exec $containerId rm -f $remotePath | Out-Null
    }
}
