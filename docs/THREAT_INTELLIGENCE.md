# Threat-intelligence enrichment

OpsAegis supports on-demand, read-only enrichment for supported public indicators.

## Supported indicators

- Public IPv4 and IPv6 addresses.
- Domains.
- HTTP(S) URLs.
- MD5, SHA-1, SHA-256 and SHA-512 hashes.

Private, loopback, link-local and reserved indicators are rejected where applicable.

## Providers

| Provider | Supported lookup scope |
|---|---|
| VirusTotal | IP, domain, URL and file-hash lookups |
| AbuseIPDB | Public IP addresses only |
| NVD | CVE metadata, not arbitrary IOC reputation |

Credentials are backend-only. Provider responses are normalized, persisted and audit logged. Repeated lookups use a bounded cache; an explicit force-refresh path is available.

## Safety and interpretation

- The workflow does not upload files or submit URLs for scanning.
- The workflow does not browse to the supplied URL.
- The workflow does not block traffic or change endpoint/firewall state.
- AbuseIPDB is not applicable to domains or file hashes.
- Provider failures and rate limits must remain errors/unavailable states, not clean verdicts.
- A source risk score is not an OpsAegis probability or guarantee.
- A CVE record does not establish that a particular asset is vulnerable.

Keep API keys out of frontend bundles and public logs. See [configuration reference](CONFIGURATION_REFERENCE.md) and [integration validation](INTEGRATION_VALIDATION.md).
