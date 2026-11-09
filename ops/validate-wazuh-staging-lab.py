#!/usr/bin/env python3
"""Offline safety checks for the pinned, local-only Wazuh staging scaffold.

This validator does not contact Docker, Wazuh, OpsAegis, or any provider.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
START = ROOT / "ops" / "wazuh-staging" / "Start-WazuhLab.ps1"
AGENT = ROOT / "ops" / "wazuh-staging" / "agent.compose.yml"
STOP = ROOT / "ops" / "wazuh-staging" / "Stop-WazuhLab.ps1"
TEST = ROOT / "ops" / "wazuh-staging" / "Test-WazuhLab.ps1"
DOC = ROOT / "docs" / "PHASE6_WAZUH_STAGING_LAB.md"


def main() -> int:
    files = (START, AGENT, STOP, TEST, DOC)
    missing = [str(path.relative_to(ROOT)) for path in files if not path.is_file()]
    if missing:
        print("BLOCKED: missing lab scaffold files: " + ", ".join(missing), file=sys.stderr)
        return 1

    start = START.read_text(encoding="utf-8")
    agent = AGENT.read_text(encoding="utf-8")
    stop = STOP.read_text(encoding="utf-8")
    test = TEST.read_text(encoding="utf-8")
    doc = DOC.read_text(encoding="utf-8")

    required_start = (
        '$WazuhTag = "v4.14.10"',
        "https://github.com/wazuh/wazuh-docker.git",
        '127.0.0.1:1514:1514',
        '127.0.0.1:1515:1515',
        '127.0.0.1:514:514/udp',
        '127.0.0.1:55000:55000',
        '127.0.0.1:9200:9200',
        '127.0.0.1:8443:5601',
        '"config", "--quiet"',
        '"up", "-d"',
    )
    missing_start = [value for value in required_start if value not in start]
    if missing_start:
        print("BLOCKED: bootstrap is missing required pinning/loopback/config checks.", file=sys.stderr)
        return 1

    if "image: wazuh/wazuh-agent:4.14.10" not in agent:
        print("BLOCKED: disposable agent image is not pinned to 4.14.10.", file=sys.stderr)
        return 1
    if "WAZUH_MANAGER_SERVER=wazuh.manager" not in agent or "ports:" in agent:
        print("BLOCKED: agent must use the private Compose network and publish no host ports.", file=sys.stderr)
        return 1
    if "-v" not in stop or "DELETE-WAZUH-LAB-DATA" not in stop:
        print("BLOCKED: volume deletion must require an explicit confirmation.", file=sys.stderr)
        return 1
    if "agent_control" not in test or "opsaegis-disposable-agent" not in test:
        print("BLOCKED: local readiness test must verify the disposable agent.", file=sys.stderr)
        return 1
    if "NOT" not in doc or "production" not in doc.lower() or "live validation" not in doc.lower():
        print("BLOCKED: documentation must state the staging/production non-claims.", file=sys.stderr)
        return 1

    print("Wazuh staging lab scaffold safety checks passed (offline only; no live validation implied).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
