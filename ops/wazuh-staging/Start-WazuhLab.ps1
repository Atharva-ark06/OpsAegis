[CmdletBinding()]
param(
    [string]$RuntimeDirectory = (Join-Path $PSScriptRoot "runtime")
)

$ErrorActionPreference = "Stop"
$WazuhTag = "v4.14.10"
$ProjectName = "opsaegis-wazuh-lab"
$AgentOverlay = Join-Path $PSScriptRoot "agent.compose.yml"
$VendorDirectory = Join-Path $RuntimeDirectory "wazuh-docker"
$SingleNodeDirectory = Join-Path $VendorDirectory "single-node"

function Assert-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found."
    }
}

function Invoke-Checked {
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

Assert-Command -Name "git"
Assert-Command -Name "docker"

$composeVersion = & docker compose version
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose v2 is required. Install or update Docker Desktop / Docker Compose."
}
Write-Host $composeVersion

if (-not (Test-Path -LiteralPath $AgentOverlay -PathType Leaf)) {
    throw "The disposable agent Compose overlay is missing: $AgentOverlay"
}

if (Test-Path -LiteralPath $VendorDirectory) {
    throw "Runtime directory already exists: $VendorDirectory. Inspect it first; this script will not overwrite or delete it."
}

New-Item -ItemType Directory -Path $RuntimeDirectory -Force | Out-Null
Invoke-Checked -Command "git" -Arguments @(
    "clone", "--depth", "1", "--branch", $WazuhTag,
    "https://github.com/wazuh/wazuh-docker.git", $VendorDirectory
)

$checkedOutTag = (& git -C $VendorDirectory describe --tags --exact-match).Trim()
if ($LASTEXITCODE -ne 0 -or $checkedOutTag -ne $WazuhTag) {
    throw "Wazuh Docker checkout is not the expected exact tag '$WazuhTag'."
}

$composeFile = Join-Path $SingleNodeDirectory "docker-compose.yml"
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "Official Wazuh single-node Compose file was not found."
}

# The upstream release binds these ports on all host interfaces by default.
# Rewrite only the exact pinned-release mappings to loopback-only host binds.
$composeText = Get-Content -LiteralPath $composeFile -Raw
$portMappings = [ordered]@{
    '- "1514:1514"' = '- "127.0.0.1:1514:1514"'
    '- "1515:1515"' = '- "127.0.0.1:1515:1515"'
    '- "514:514/udp"' = '- "127.0.0.1:514:514/udp"'
    '- "55000:55000"' = '- "127.0.0.1:55000:55000"'
    '- "9200:9200"' = '- "127.0.0.1:9200:9200"'
    '- 443:5601' = '- "127.0.0.1:8443:5601"'
}
foreach ($entry in $portMappings.GetEnumerator()) {
    $count = ([regex]::Matches($composeText, [regex]::Escape($entry.Key))).Count
    if ($count -ne 1) {
        throw "Expected exactly one upstream port mapping '$($entry.Key)'; found $count. Refusing an unreviewed rewrite."
    }
    $composeText = $composeText.Replace($entry.Key, $entry.Value)
}
Set-Content -LiteralPath $composeFile -Value $composeText -Encoding utf8

Push-Location $SingleNodeDirectory
try {
    $projectArgs = @("-p", $ProjectName)

    Write-Host "Generating local self-signed certificates using the pinned Wazuh release tooling..."
    Invoke-Checked -Command "docker" -Arguments (@("compose") + $projectArgs + @(
        "-f", "generate-indexer-certs.yml", "run", "--rm", "generator"
    ))

    Write-Host "Validating the combined Compose configuration..."
    Invoke-Checked -Command "docker" -Arguments (@("compose") + $projectArgs + @(
        "-f", "docker-compose.yml", "-f", $AgentOverlay, "config", "--quiet"
    ))

    Write-Host "Starting the isolated Wazuh single-node stack and disposable agent..."
    Invoke-Checked -Command "docker" -Arguments (@("compose") + $projectArgs + @(
        "-f", "docker-compose.yml", "-f", $AgentOverlay, "up", "-d"
    ))

    Write-Host ""
    Write-Host "Lab containers:"
    Invoke-Checked -Command "docker" -Arguments (@("compose") + $projectArgs + @(
        "-f", "docker-compose.yml", "-f", $AgentOverlay, "ps"
    ))
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Wazuh lab bootstrap finished. Container startup is not proof of agent enrollment or telemetry ingestion."
Write-Host "Dashboard: https://localhost:8443 (self-signed lab certificate)"
Write-Host "Manager API: https://localhost:55000 (host loopback only)"
Write-Host "Indexer API: https://localhost:9200 (host loopback only)"
Write-Host "Run Test-WazuhLab.ps1 after the services finish initializing."
Write-Warning "This is a disposable local lab only. Do not connect production agents, expose ports, or reuse its default credentials."
