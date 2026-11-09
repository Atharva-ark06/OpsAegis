[CmdletBinding()]
param(
    [string]$RuntimeDirectory = (Join-Path $PSScriptRoot "runtime"),
    [switch]$RemoveVolumes
)

$ErrorActionPreference = "Stop"
$ProjectName = "opsaegis-wazuh-lab"
$SingleNodeDirectory = Join-Path (Join-Path $RuntimeDirectory "wazuh-docker") "single-node"
$AgentOverlay = Join-Path $PSScriptRoot "agent.compose.yml"

if (-not (Test-Path -LiteralPath $SingleNodeDirectory)) {
    Write-Host "No local Wazuh lab checkout found; nothing to stop."
    return
}

Push-Location $SingleNodeDirectory
try {
    $composeArgs = @(
        "compose", "-p", $ProjectName,
        "-f", "docker-compose.yml",
        "-f", $AgentOverlay,
        "down"
    )
    if ($RemoveVolumes) {
        Write-Warning "This permanently deletes the disposable Wazuh lab data volumes."
        $confirmation = Read-Host "Type DELETE-WAZUH-LAB-DATA to confirm"
        if ($confirmation -cne "DELETE-WAZUH-LAB-DATA") {
            throw "Volume deletion was not confirmed."
        }
        $composeArgs += "-v"
    }

    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Wazuh lab teardown failed."
    }
}
finally {
    Pop-Location
}
