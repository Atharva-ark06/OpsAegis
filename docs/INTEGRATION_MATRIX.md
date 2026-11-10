# Integration capability and safety matrix

A configured integration is not necessarily a validated integration. Use the status and evidence registers to distinguish code, credentials, connectivity, ingestion and production acceptance.

| Integration | Primary capability | Direction | Credential scope | Important limitation |
|---|---|---|---|---|
| Wazuh Manager | Read registered-agent inventory | Read-only pull | API | Does not enroll, restart or disconnect agents |
| Wazuh Indexer | Read alert and vulnerability-state records | Read-only pull | API / dedicated collection process | Bounded queries; truncation must be surfaced |
| CrowdSec LAPI | Read active decisions | Read-only pull | Dedicated bouncer key | Does not create/delete decisions |
| CrowdSec alert history | Read bounded alert history | Read-only pull | Optional dedicated machine account | Broader machine permissions; disabled unless configured |
| VirusTotal | Enrich supported IOCs | Read-only lookup | API | No file upload or URL visit by this workflow |
| AbuseIPDB | Enrich public IP indicators | Read-only lookup | API | Not applicable to domains, hashes or private IPs |
| NVD | Retrieve CVE metadata | Read-only lookup | Optional API key | CVE presence does not prove an asset is affected |
| Nuclei | Authorized vulnerability scan | Gated execution | Isolated scanner worker | Disabled until authorization and external egress controls pass |
| Shannon | Authorized AI-assisted application testing | External runner | Isolated bridge token | Staging/lab only; never production |
| Playbooks | Preview and approval governance | No provider dispatch | Application roles | Approval does not execute response actions |

## Validation levels

1. **Implemented:** adapter or UI code exists.
2. **Configured:** required endpoint and credentials are present.
3. **Connected:** a bounded health request succeeds.
4. **Ingesting:** expected source records are observed and reconciled.
5. **Operationally accepted:** recovery, access control, provenance and failure cases have been tested with retained evidence.

Do not label an integration live based only on a configuration flag, health badge, mocked test or CI result.

## Safe operating defaults

- Read-only integrations use bounded timeouts and result limits.
- TLS verification remains enabled.
- Provider errors and rate limits are not treated as clean results.
- Scanner targets require explicit authorization and allowlisting.
- Scanner execution must be isolated from the API process and public data services.
- No response action should be enabled without a separate threat model, least-privilege credential, approval design and audit coverage.

See [live integration validation](INTEGRATION_VALIDATION.md), [Nuclei worker deployment](NUCLEI_WORKER.md), [Shannon runner](SHANNON_RUNNER.md) and [release readiness](RELEASE_READINESS.md).
