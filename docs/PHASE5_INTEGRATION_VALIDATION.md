# Phase 5 Integration Validation

This runbook separates automated regression coverage from proof obtained against real services. A green CI run validates code paths and mocked contracts; it does not establish that an external engine is reachable or that production telemetry is flowing.

## Automated ingestion contract tests

Run from the repository root:

```powershell
cd backend
python -m pytest tests/test_integrations.py tests/test_integration_ingestion_contracts.py tests/test_wazuh_adapter.py tests/test_wazuh_manager_adapter.py tests/test_crowdsec_adapter.py -q
```

The integration-ingestion contract tests verify:

- CrowdSec active-decision collection is idempotent, audited and does not overwrite analyst triage or first-seen time.
- Wazuh Manager inventory refresh updates source-owned endpoint observations while preserving analyst-managed asset type and environment.
- Wazuh Vulnerability Detector refresh updates source-derived CVE/package severity while preserving analyst remediation state, notes and NVD cache metadata.
- Viewer accounts cannot trigger the tested integration sync operations.

These tests use mocked adapters and a disposable SQLite test database. They do not call Wazuh, CrowdSec, VirusTotal, AbuseIPDB, NVD or Shannon, and they do not launch Nuclei.

## Live service validation

Run the existing read-only diagnostic from the deployment host/network with operator-owned credentials:

```powershell
python backend/scripts/validate_integrations.py --env-file .env --output artifacts/integration-diagnostics.json
```

The report checks database and Redis connectivity, the detection-worker heartbeat (required in production), and the isolated Nuclei-worker heartbeat when both Nuclei enablement flags are set. It then checks configured Wazuh Manager, Wazuh Indexer, CrowdSec and Shannon endpoints. The report distinguishes passed, failed, skipped and not-probed checks. A skipped or not-probed result is not a pass. VirusTotal and AbuseIPDB are not queried by this diagnostic to avoid unexpected quota consumption. Add `--include-nvd` only when one public NVD lookup is explicitly intended. The diagnostic never launches Nuclei or changes application data.

After endpoint diagnostics pass, perform separately authorized, bounded validation of:
1. Wazuh Manager inventory sync and Wazuh Indexer alert/vulnerability collection using a disposable lab agent and known test events.
2. CrowdSec active-decision collection using a test decision with a short expiry; verify that the integration is read-only and does not create/delete decisions.
3. Threat-intelligence lookups using operator-selected public test indicators, while monitoring provider quota and retaining sanitized results only.
4. Shannon bridge health and a single explicitly authorized disposable target assessment, after VM isolation and egress controls are independently verified.
5. Nuclei only after external DNS/IP egress enforcement and written target authorization are verified; keep both enablement flags disabled otherwise.

For each live test, record the service/version, timestamp, test identity, result counts, truncation state and sanitized error category. Do not attach API keys, authorization headers, raw response bodies or sensitive event payloads to the report.

## Exit criteria

Phase 5 cannot be marked complete solely because these tests pass. It also requires live service validation from the intended deployment network, worker restart/recovery drills, production deployment and migration verification, backup/restore evidence, monitoring/alerting, and a final security review. Record unavailable integrations as blocked rather than passed.
