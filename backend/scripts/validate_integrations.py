from __future__ import annotations

import argparse
import asyncio
import json
import os
import inspect
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DETECTION_HEARTBEAT = "opsaegis:detection:worker:heartbeat"
NUCLEI_HEARTBEAT = "opsaegis:nuclei:worker:heartbeat"


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
    performed = counts.get("passed", 0) + counts.get("failed", 0)
    configured_but_unprobed = counts.get("not_probed", 0)
    if counts.get("failed", 0):
        overall = "failed"
    elif performed == 0 and configured_but_unprobed == 0:
        overall = "no_configured_integrations"
    elif configured_but_unprobed:
        overall = "partial"
    else:
        overall = "passed"
    return overall, counts


def heartbeat_check(
    name: str,
    client: Any,
    key: str,
    *,
    enabled: bool,
    missing_status: str = "failed",
) -> dict[str, str]:
    """Return a sanitized status for a Redis-backed worker heartbeat."""
    if not enabled:
        return {"name": name, "status": "skipped", "detail": "Worker is not enabled"}
    try:
        alive = bool(client.get(key))
    except Exception as exc:
        return {"name": name, "status": "failed", "detail": type(exc).__name__}
    if alive:
        return {"name": name, "status": "passed", "detail": "Active Redis heartbeat observed"}
    detail = "No active Redis heartbeat observed"
    if missing_status == "skipped":
        detail = "No heartbeat observed in this non-production environment"
    return {"name": name, "status": missing_status, "detail": detail}


def nuclei_worker_check(config: Any, client: Any) -> dict[str, str]:
    """Check the isolated Nuclei worker; never start a scan or enable execution."""
    if not config.nuclei_enabled and not config.nuclei_worker_enabled:
        return {"name": "nuclei_worker", "status": "skipped", "detail": "Nuclei execution is disabled"}
    if config.nuclei_enabled != config.nuclei_worker_enabled:
        return {
            "name": "nuclei_worker",
            "status": "failed",
            "detail": "NUCLEI_ENABLED and NUCLEI_WORKER_ENABLED must both be true",
        }
    return heartbeat_check("nuclei_worker", client, NUCLEI_HEARTBEAT, enabled=True)


def detection_worker_check(config: Any, client: Any) -> dict[str, str]:
    """Require a live detection worker in production; keep dev-only setups explicit."""
    return heartbeat_check(
        "detection_worker",
        client,
        DETECTION_HEARTBEAT,
        enabled=True,
        missing_status="failed" if config.environment.lower() == "production" else "skipped",
    )


async def run_checks(include_nvd: bool) -> dict[str, Any]:
    # Imports occur after the CLI has loaded the selected env file.
    backend_root = str(Path(__file__).resolve().parents[1])
    if backend_root not in sys.path:
        sys.path.insert(0, backend_root)

    from redis import Redis
    from sqlalchemy import text

    from app.config import Settings
    from app.database import engine
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
            result = operation()
            if inspect.isawaitable(result):
                result = await result
            if result is False or result is None:
                raise RuntimeError("unhealthy_response")
            checks.append({"name": name, "status": "passed", "detail": detail})
        except Exception as exc:  # Never print response bodies or credentials.
            checks.append({"name": name, "status": "failed", "detail": type(exc).__name__})

    def database_ping() -> bool:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True

    await probe("database", True, database_ping, detail="Database SELECT 1 succeeded")

    redis_client = Redis.from_url(
        config.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    redis_available = False
    try:
        try:
            redis_available = bool(redis_client.ping())
            if not redis_available:
                raise RuntimeError("redis_unhealthy")
            checks.append({"name": "redis", "status": "passed", "detail": "Redis PING succeeded"})
        except Exception as exc:
            checks.append({"name": "redis", "status": "failed", "detail": type(exc).__name__})
        if redis_available:
            checks.append(detection_worker_check(config, redis_client))
            checks.append(nuclei_worker_check(config, redis_client))
        else:
            checks.append({"name": "detection_worker", "status": "failed", "detail": "Redis unavailable; heartbeat cannot be checked"})
            if config.nuclei_enabled or config.nuclei_worker_enabled:
                checks.append({"name": "nuclei_worker", "status": "failed", "detail": "Redis unavailable; heartbeat cannot be checked"})
            else:
                checks.append({"name": "nuclei_worker", "status": "skipped", "detail": "Nuclei execution is disabled"})
    finally:
        redis_client.close()

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
            "status": "skipped",
            "detail": "Optional probe not requested; use --include-nvd for one public CVE lookup",
        })

    overall, counts = summarize(checks)
    return {
        "tool": "OpsAegis operational diagnostics",
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
        description="Run bounded, read-only service, worker and integration health checks."
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Local env file to load (default: .env in the current directory)",
    )
    parser.add_argument(
        "--include-nvd",
        action="store_true",
        help="Make one read-only lookup for the fixed public CVE-2021-44228",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for a JSON report; the report never contains credentials",
    )
    args = parser.parse_args()

    for key, value in parse_env_file(args.env_file).items():
        os.environ.setdefault(key, value)

    try:
        report = asyncio.run(run_checks(args.include_nvd))
    except Exception as exc:
        report = {
            "tool": "OpsAegis operational diagnostics",
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

    if report["overall"] in {"failed", "configuration_error"}:
        return 1
    if report["overall"] == "no_configured_integrations":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
