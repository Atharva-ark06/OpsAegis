# Threat-intelligence enrichment

OpsAegis supports on-demand, read-only enrichment for supported public indicators and combines source-attributed evidence from VirusTotal and AbuseIPDB.

## Supported indicators

- Public IPv4 and IPv6 addresses.
- Domains.
- HTTP(S) URLs.
- MD5, SHA-1, SHA-256 and SHA-512 hashes.

Private, loopback, link-local and reserved indicators are rejected where applicable.

## Providers and report evidence

| Provider | Supported lookup scope | Evidence included |
|---|---|---|
| VirusTotal | IP, domain, URL and file-hash lookups | Analysis counts, individual malicious/suspicious engine flags, engine result labels, classifications, tags, reputation, network/ASN/owner/country, registration and analysis timestamps, DNS metadata and community votes when returned by the API |
| AbuseIPDB | Public IP addresses only | Abuse confidence, report count, distinct reporters, ISP/domain/hostnames, country, usage type, whitelist/public flags, last report date and a bounded sample of report categories/comments |

The combined verdict prioritizes malicious over suspicious, then clean only when successful configured providers have returned clean results. The combined score is the highest available provider score, not a probability or an average. When providers disagree, the UI highlights the disagreement and retains both provider reports separately.

AbuseIPDB is not applicable to domains, URLs or file hashes. Those lookups use VirusTotal and explicitly show AbuseIPDB as not applicable.

Credentials are backend-only. Provider responses are normalized, bounded and persisted with audit records. Repeated lookups use a bounded cache; an explicit force-refresh path is available. VirusTotal detection flags are limited to the first 100 malicious/suspicious engine results; AbuseIPDB report history is limited to 20 reports and comments are truncated.

## Safety and interpretation

- The workflow does not upload files or submit URLs for scanning.
- The workflow does not browse to the supplied URL.
- The workflow does not block traffic or change endpoint/firewall state.
- Provider failures, rate limits, authentication errors and missing records remain unavailable states, not clean verdicts.
- Provider-specific classifications and scores are displayed as reported; OpsAegis does not claim they are independently verified.
- A clean result is not proof that an indicator is safe. A source risk score is not an OpsAegis probability or guarantee.
- API plans may limit fields, report history and request frequency. Empty evidence means the provider did not return that field, not that the field is negative.

Keep API keys out of frontend bundles and public logs. See [configuration reference](CONFIGURATION_REFERENCE.md) and [integration validation](INTEGRATION_VALIDATION.md).
