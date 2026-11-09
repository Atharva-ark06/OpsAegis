[CmdletBinding()]
param(
    [string]$RuntimeDirectory = (Join-Path $PSScriptRoot "runtime")
)

$ErrorActionPreference = "Stop"
$ProjectName = "opsaegis-wazuh-lab"
$VendorDirectory = Join-Path $RuntimeDirectory "wazuh-docker"
$SingleNodeDirectory = Join-Path $VendorDirectory "single-node"
$AgentOverlay = Join-Path $PSScriptRoot "agent.compose.yml"

foreach ($path in @($SingleNodeDirectory, $AgentOverlay)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Wazuh lab file or runtime directory is missing: $path. Run Start-WazuhLab.ps1 first."
    }
}

Push-Location $SingleNodeDirectory
try {
    $composeArgs = @(
        "compose", "-p", $ProjectName,
        "-f", "docker-compose.yml",
        "-f", $AgentOverlay
    )

    Write-Host "Current Wazuh lab container state:"
    & docker @($composeArgs + @("ps"))
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Wazuh lab Compose status."
    }

    Write-Host "Checking that the disposable agent enrolled and is active..."
    $agentOutput = & docker @($composeArgs + @(
        "exec", "-T", "wazuh.manager", "/var/ossec/bin/agent_control", "-l"
    ))
    if ($LASTEXITCODE -ne 0) {
        throw "Wazuh manager agent inventory command failed. Check container logs and wait for startup."
    }

    $agentText = $agentOutput -join "`n"
    if ($agentText -notmatch "opsaegis-disposable-agent") {
        throw "The disposable agent is not present in the manager inventory yet."
    }
    if ($agentText -notmatch "(?i)Active") {
        throw "The disposable agent is present but is not reported active."
    }

    Write-Host "PASS: disposable agent is listed as active in the local Wazuh Manager."
    Write-Host "This check does not validate OpsAegis ingestion, isolation, unisolation, or recovery."
}
finally {
    Pop-Location
}
