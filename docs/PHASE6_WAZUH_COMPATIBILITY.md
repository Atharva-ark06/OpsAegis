# Wazuh integration compatibility and validation

**Compatibility target:** Wazuh 4.14.x API surface  
**Validation status:** Mocked regression coverage only; no live Wazuh Manager or Indexer has been contacted for this change.  
**Scope:** Existing read-only inventory, alert, and vulnerability collection adapters.

The 4.14.x target is a documentation and test baseline, not a claim about the version deployed by an OpsAegis operator. Confirm the actual Manager and Indexer versions before enabling a live connection. The current official Wazuh documentation exposes the 4.14.10 Server API reference and the 4.14 Indexer API reference.

## Read-only API surface

| Component | Request | Purpose |
|---|---|---|
| Wazuh Manager | `POST /security/user/authenticate` using HTTP Basic authentication | Obtain a short-lived JWT |
| Wazuh Manager | `GET /` with Bearer JWT | Read API information / health |
| Wazuh Manager | `GET /agents` with Bearer JWT and bounded `limit`, `offset`, and `select` | Read endpoint inventory |
| Wazuh Indexer | `GET /_cluster/health` using configured Indexer authentication | Read cluster health |
| Wazuh Indexer | `POST /wazuh-alerts-*/_search` using configured Indexer authentication | Read alert documents |
| Wazuh Indexer | `POST /wazuh-states-vulnerabilities-*/_search` using configured Indexer authentication | Read vulnerability state documents |

The Indexer `POST .../_search` calls are query operations; they do not write documents or change cluster configuration. No Manager active-response, agent isolation, unisolation, restart, or other mutation endpoint is part of these adapters.

## Compatibility and safety controls

- Manager and Indexer origins must be HTTPS, contain no embedded credentials, and contain no URL path, query, or fragment.
- Redirects and ambient proxy environment variables are disabled for adapter clients.
- TLS verification is mandatory. Configure the appropriate CA bundle for private PKI; do not disable verification.
- Manager inventory pagination is bounded to 500 records per page and a configured maximum of 2,000 agents.
- Manager responses must have the documented `data.affected_items` and `data.total_affected_items` shape. Malformed rows, boolean totals, and oversized pages fail closed.
- Manager JWTs must be non-empty and contain no whitespace before being placed in the Bearer header.
- Alert search patterns are restricted to the `wazuh-alerts-` namespace. Broad patterns such as `*`, `_all`, and comma-separated cross-index patterns are rejected.
- Search results marked timed out or reporting failed shards are rejected rather than treated as complete.
- Vulnerability queries use the documented `wazuh-states-vulnerabilities-*` index pattern.
- Alert evidence remains normalized and bounded; arbitrary raw event payloads such as `full_log` are not copied into normalized evidence.

## Operator checklist before live validation

1. Record the exact Wazuh Manager and Indexer versions and confirm they are compatible with the intended 4.14.x baseline.
2. Confirm that the Manager account is a dedicated read-only identity with only the permissions required for API information and agent inventory.
3. Confirm that the Indexer account can read only the required alert and vulnerability indices.
4. Provision credentials through the deployment's secret-management process. Do not commit credentials, tokens, or private CA material.
5. Configure trusted CA bundles and verify that TLS validation succeeds from the OpsAegis runtime network.
6. Run the existing read-only diagnostics and inspect sanitized results. A successful health check proves only a point-in-time API response; it does not prove complete telemetry ingestion or data freshness.
7. Validate alert and vulnerability collection with authorized test data and record sanitized evidence separately from source payloads.

Do not use production endpoints for exploratory testing. Do not run isolation, active response, scans, or other state-changing actions as part of this checklist.

## References

- [Wazuh Server API reference (4.14.10)](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh Server API authentication and getting started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- [Wazuh Indexer API reference (4.14)](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html)
- [Wazuh Indexer indices and index patterns](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)

## Explicit non-claims

This document and its mocked tests do not establish the operator's deployed Wazuh version, live connectivity, service-account permissions, certificate deployment, upstream index availability, telemetry completeness, production health, or authorization for response actions. Wazuh isolation and unisolation remain disabled and unregistered pending the separate security and staging gates in [the isolation threat model](./PHASE6_WAZUH_ISOLATION_THREAT_MODEL.md).
