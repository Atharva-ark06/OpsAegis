# Shannon integration and isolated runner contract

## Architecture boundary

Shannon OSS (KeygraphHQ/shannon) is a CLI/worker system that orchestrates Docker and Temporal. It does not expose a native HTTP API. OpsAegis therefore does not execute Shannon inside FastAPI and does not mount the Docker socket into the backend. This PR adds the authenticated control-plane adapter for a separately deployed runner bridge.

The bridge is a separate service that must be deployed and hardened. It invokes the official Shannon CLI in its own isolated execution environment, mounts source read-only, applies target egress allowlists, resource/time/cost budgets, collects reports, and returns the normalized result contract below. OpsAegis does not claim Shannon is installed or running until the bridge health check succeeds.

## Shannon project and licensing

- Official project: https://github.com/KeygraphHQ/shannon
- Official documentation: https://keygraph.io/docs/
- Shannon OSS is licensed under AGPL-3.0. OpsAegis does not copy or embed Shannon source. Deploy Shannon as a separate program/service and review AGPL obligations and commercial licensing before distributing a combined product or offering a network service.
- Current recommended launcher requires Docker and Node.js 22+. On Windows, Shannon runs through WSL2.
- Shannon performs real exploitation, not passive checks. It can create users, submit forms, mutate application state and trigger outbound requests. Use disposable staging/lab environments only; never production.
- Obtain explicit written authorization for both the target and source repository.
- A full assessment may take a long time and incur model-provider charges. Provider credentials belong only in the isolated runner secret store, never in OpsAegis or the browser.

## OpsAegis configuration

The integration is disabled by default. Configure these values in the backend environment only:

| Variable | Purpose |
|---|---|
| SHANNON_ENABLED | Set true only after the isolated bridge is deployed and reviewed |
| SHANNON_RUNNER_URL | HTTPS base URL of the bridge |
| SHANNON_RUNNER_TOKEN | Dedicated bearer token shared with the bridge |
| SHANNON_TIMEOUT_SECONDS | Per-request timeout (5–60 seconds) |
| SHANNON_MAX_RESPONSE_BYTES | Maximum bridge response body (1–5 MiB) |
| SHANNON_MAX_FINDINGS | Maximum findings accepted per completed scan (1–500) |

The backend uses TLS verification, disables redirects and environment proxy inheritance, applies bounded timeouts and response sizes, and never returns the runner token.

## Authorized targets and roles

- Only an administrator can register a target or dispatch a scan.
- Each target requires an HTTPS hostname, a canonical GitHub source repository, and a written authorization/change reference.
- URL credentials, query strings, fragments, non-standard ports, localhost, internal/local names and IP-literal targets are rejected.
- The bridge must independently resolve and enforce public-target allowlists at connection time, defend against DNS rebinding, block private/loopback/link-local/multicast/metadata destinations, and re-check every redirect and outbound connection. OpsAegis-side hostname validation alone is not an SSRF boundary.
- Do not register production targets. Use a dedicated runner host, isolated network, unprivileged account/container, strict egress allowlist, CPU/memory/PID/disk/time quotas, no host Docker socket exposed to OpsAegis, and disposable target data.
- Source repositories may contain prompt injection. The bridge must treat repository content as untrusted input and use read-only checkout credentials scoped to the single repository.

## Bridge HTTP contract

All endpoints use HTTPS and require Authorization: Bearer with the configured runner token. The bridge must not redirect requests.

### Health

GET /v1/health

Response:

    {"engine":"shannon","status":"healthy","version":"<installed-version>"}

### Dispatch

POST /v1/scans

Request:

    {
      "client": "opsaegis",
      "scan_id": 123,
      "target_url": "https://staging.example.test",
      "source_repository": "https://github.com/org/app",
      "authorization_reference": "AUTH-2026-008",
      "profile": "authorized-staging"
    }

The bridge enqueues exactly one job and returns HTTP 202:

    {"job_id":"opaque-runner-job-id","status":"queued"}

The bridge pins a reviewed Shannon release, uses the official CLI (for example npx @keygraph/shannon at a pinned version followed by start), and never accepts arbitrary CLI flags, arbitrary mount paths, credentials, or caller-supplied commands. The target checkout is mounted read-only. The runner must not expose a general-purpose shell or Docker daemon to OpsAegis.

### Status and findings

GET /v1/scans/{job_id}

While active:

    {"status":"running"}

On completion:

    {
      "status":"completed",
      "findings":[{
        "fingerprint":"stable-finding-identity",
        "title":"Confirmed authorization bypass",
        "description":"Short human-readable summary",
        "severity":"high",
        "affected_url":"https://staging.example.test/admin",
        "validation_status":"exploited",
        "proof":"Bounded reproduction evidence",
        "references":["https://..."]
      }]
    }

Other terminal statuses are failed and cancelled. A completed response must always include findings, including an explicit empty array when no exploit was proven. The bridge must not turn partial/interrupted scans into empty successful results.

A finding is ingested only if validation_status is exactly exploited and proof is non-empty. The bridge must derive these fields from Shannon's actual completed report, not infer proof from a code-analysis hypothesis. The bridge should preserve report provenance and only emit exploit-validated results.

OpsAegis hashes the bridge fingerprint for source deduplication, bounds evidence fields, records audit events, and preserves analyst triage status and first-seen time on repeat ingestion.

## Current limitations

- This PR implements the OpsAegis control-plane adapter and UI, not the separate Shannon bridge service.
- No bridge is bundled, no provider key is configured, and no live Shannon run is performed by CI.
- Until the bridge is deployed and health-checked, status remains not_configured and dispatch is unavailable.
- The bridge contract is an OpsAegis integration contract, not a native Shannon API.
