from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE entries without interpolation or shell execution."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key or not key.replace("_", "A").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def summarize(checks: list[dict[str, str]]) -> tuple[str, dict[str, int]]:
    counts = dict(Counter(item["status"] for item in checks))
    configured = sum(counts.get(status, 0) for status in ("passed", "failed", "not_probed"))
    if counts.get("failed", 0):
        overall = "failed"
    elif configured == 0:
        overall = "no_configured_integrations"
    elif counts.get("not_probed", 0):
        overall = "partial"
    else:
        overall = "passed"
    return overall, counts


async def run_checks(include_nvd: bool) -> dict[str, Any]:
    # Imports occur after the CLI has loaded the selected env file.
    backend_root = str(Path(__file__).resolve().parents[1])
    if backend_root not in sys.path:
        sys.path.insert(0, backend_root)

    from app.config import Settings
    from app.integrations.crowdsec import CrowdSecLapiAdapter
    from app.integrations.nvd import NVDAdapter
    from app.integrations.shannon import ShannonRunnerAdapter
    from app.integrations.wazuh import WazuhIndexerAdapter
    from app.integrations.wazuh_manager import WazuhManagerAdapter

    config = Settings(_env_file=None)
    checks: list[dict[str, str]] = []

    async def probe(name: str, configured: bool, operation, *, detail: str = "Read-only health request completed") -> None:
        if not configured:
            checks.append({"name": name, "status": "skipped", "detail": "Not configured"})
            return
        try:
            result = await operation()
            if result is False or result is None:
                raise RuntimeError("unhealthy_response")
            checks.append({"name": name, "status": "passed", "detail": detail})
        except Exception as exc:  # Adapter errors are sanitized; never print response bodies or credentials.
            checks.append({"name": name, "status": "failed", "detail": type(exc).__name__})

    manager = WazuhManagerAdapter(config)
    indexer = WazuhIndexerAdapter(config)
    crowdsec = CrowdSecLapiAdapter(config)
    shannon = ShannonRunnerAdapter()

    await probe("wazuh_manager", manager.is_configured, manager.healthcheck)
    await probe("wazuh_indexer", indexer.is_configured, indexer.healthcheck)
    await probe("crowdsec_lapi", crowdsec.is_configured, crowdsec.healthcheck)
    await probe(
        "shannon_runner",
        shannon.is_configured,
        shannon.healthcheck,
        detail="Authenticated runner health endpoint responded",
    )

    if config.virustotal_api_key:
        checks.append({
            "name": "virustotal",
            "status": "not_probed",
            "detail": "Configured; no lookup was sent, to avoid consuming API quota",
        })
    else:
        checks.append({"name": "virustotal", "status": "skipped", "detail": "Not configured"})

    if config.abuseipdb_api_key:
        checks.append({
            "name": "abuseipdb",
            "status": "not_probed",
            "detail": "Configured; no lookup was sent, to avoid consuming API quota",
        })
    else:
        checks.append({"name": "abuseipdb", "status": "skipped", "detail": "Not configured"})

    if config.nuclei_enabled:
        checks.append({
            "name": "nuclei",
            "status": "failed",
            "detail": "NUCLEI_ENABLED is true; the legacy API-process scanner must remain disabled",
        })
    else:
        checks.append({
            "name": "nuclei",
            "status": "skipped",
            "detail": "Execution is disabled; this diagnostic never launches a scan",
        })

    if include_nvd:
        await probe(
            "nvd_public_api",
            True,
            lambda: NVDAdapter(config).lookup("CVE-2021-44228"),
            detail="Read-only lookup of a fixed public CVE completed",
        )
    else:
        checks.append({
            "name": "nvd_public_api",
            "status": "not_probed",
            "detail": "Use --include-nvd to make one read-only public CVE lookup",
        })

    overall, counts = summarize(checks)
    return {
        "tool": "OpsAegis integration diagnostics",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": config.environment,
        "overall": overall,
        "summary": counts,
        "checks": checks,
        "safety": {
            "scans_launched": False,
            "configuration_changed": False,
            "secrets_printed": False,
            "provider_ioc_lookups_sent": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run bounded, read-only health checks for configured OpsAegis integrations."
    )
    parser.add_argument("--env-file", type=Path, default=Path(".env"),
                        help="Local env file to load (default: .env in the current directory)")
    parser.add_argument("--include-nvd", action="store_true",
                        help="Make one read-only lookup for the fixed public CVE-2021-44228")
    parser.add_argument("--output", type=Path,
                        help="Optional path for a JSON report; the report never contains credentials")
    args = parser.parse_args()

    for key, value in parse_env_file(args.env_file).items():
        os.environ.setdefault(key, value)

    try:
        report = asyncio.run(run_checks(args.include_nvd))
    except Exception as exc:
        report = {
            "tool": "OpsAegis integration diagnostics",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall": "configuration_error",
            "error_type": type(exc).__name__,
            "safety": {
                "scans_launched": False,
                "configuration_changed": False,
                "secrets_printed": False,
                "provider_ioc_lookups_sent": False,
            },
        }

    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")

    if report["overall"] == "failed" or report["overall"] == "configuration_error":
        return 1
    if report["overall"] == "no_configured_integrations":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
