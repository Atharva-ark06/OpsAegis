# OpsAegis live integration validation

This procedure helps an operator verify configured external services from the same Python environment and network path used by OpsAegis. It is a diagnostic, not a deployment certification.

## Run it

From the repository root, after putting real service credentials in the local, untracked \`.env\` file:

\`\`\`powershell
python backend/scripts/validate_integrations.py --env-file .env --output artifacts/integration-diagnostics.json
\`\`\`

The script first checks database and Redis reachability, then checks the Redis heartbeats for the detection worker and (when enabled) the isolated Nuclei worker. In production, a missing detection-worker heartbeat fails the report. It also uses the existing read-only adapters for Wazuh Manager, Wazuh Indexer, CrowdSec LAPI and the configured Shannon runner. Remote adapters verify TLS certificates, do not follow redirects, and do not inherit ambient HTTP proxy settings. Missing optional integrations are reported as skipped.

To additionally verify public NVD reachability, opt in to one read-only lookup of the fixed public CVE-2021-44228:

\`\`\`powershell
python backend/scripts/validate_integrations.py --env-file .env --include-nvd
\`\`\`

VirusTotal and AbuseIPDB are reported as configured-but-not-probed when keys exist. The script deliberately does not send an IOC lookup, so it does not consume provider quota. Use the normal authenticated OpsAegis threat-intelligence workflow when you intend to spend a lookup.

## Result meanings

| Status | Meaning |
| --- | --- |
| \`passed\` | A bounded read-only health request succeeded. |
| \`failed\` | A configured service could not pass its health check. The detail is a sanitized exception type, not a response body. |
| \`skipped\` | The service is not configured, or execution is intentionally disabled. |
| \`not_probed\` | Configuration exists, but no request was made (for example, provider quota protection). |

Overall status is \`passed\` only when at least one service was checked and every performed check passed. \`partial\` means at least one configured provider was intentionally not probed. \`no_configured_integrations\` is not a successful validation. A non-zero exit code indicates a failed check or no configured integration.

## Safety boundaries

- No scan is launched, no target is contacted by a scanner, and no database record is created or changed.
- No integration credential, token, response body or authorization header is printed or written to the report.
- Wazuh Manager, Indexer, CrowdSec and Shannon checks are read-only health calls through existing adapters.
- NVD lookup is opt-in and uses one fixed public CVE identifier.
- VirusTotal and AbuseIPDB lookups are intentionally omitted to avoid unexpected quota use.
- Nuclei scans are never launched by this diagnostic. When both \`NUCLEI_ENABLED\` and \`NUCLEI_WORKER_ENABLED\` are false, the isolated scanner is reported as skipped. If both are true, the diagnostic requires a current Redis heartbeat from the dedicated worker. A mismatched pair of flags or a missing heartbeat is a failure. This heartbeat check is not proof of enforced scanner egress controls or authorization.
- A passing result validates only the checked dependency or heartbeat at that moment. It does not prove telemetry ingestion, event freshness, permissions beyond the health request, worker recovery under failure, scanner egress isolation, backup/restore, or production readiness.

## Troubleshooting

1. Confirm the local \`.env\` file is not committed and contains the correct service URL and credentials.
2. Use HTTPS URLs and install the issuing private CA bundle where applicable; never disable certificate verification.
3. Check firewall rules, DNS resolution and service availability from the host/container where OpsAegis runs.
4. For Wazuh Manager, use a least-privilege account that can authenticate and read the API root.
5. For Wazuh Indexer, use a read-only account with access to cluster health.
6. For CrowdSec, use a dedicated read-only bouncer key.
7. For Shannon, configure the external runner only after its isolation and egress controls have been independently reviewed.

Do not paste the generated report if it contains internal hostnames or infrastructure details you do not want to share. Review it before sharing.
