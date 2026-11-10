# Security model

## Identity and authorization

OpsAegis uses authenticated sessions, server-side role resolution and role-gated API operations. The workspace distinguishes viewer, analyst and administrator capabilities. Administrative bootstrap is a controlled first-account flow, not open self-registration.

Authorization must be enforced by the API. Hiding a button in the frontend is not a security boundary.

## Secret handling

- Provider keys and passwords stay in backend service variables.
- Signing and worker secrets are distinct.
- Dedicated integration accounts should have the narrowest read permissions possible.
- Private CA certificates may be mounted read-only where required; private keys must not be placed in public repository paths.
- Secrets must never be logged, exported to the browser or embedded in build artifacts.

## Network boundaries

- Public access terminates at the frontend HTTPS endpoint or a trusted TLS reverse proxy.
- API, PostgreSQL and Redis should remain private.
- The frontend proxies API traffic; the browser does not connect to internal service hosts.
- Scanner and AI-runner egress must be restricted outside the application, including DNS resolution and private/metadata address ranges.

## Data protection

Incident notes, uploaded evidence, exports and backups may contain sensitive operational information. Apply role checks, size limits, content validation, no-store response headers, retention controls and encrypted off-host backup storage. Review exports before sharing.

## Safe integration behavior

Read-only adapters should use bounded requests, validate upstream responses, preserve provenance and avoid mutating upstream systems. An error, missing provider or truncated response must not be represented as a clean security result.

Nuclei and Shannon are intentionally gated. Do not enable them until written authorization, isolated execution, strict egress controls, resource limits and audit requirements are satisfied.

## Known limitations

The repository's security controls and CI checks do not certify the security of a deployed host, cloud account, provider credential, network firewall or external runner. Staging acceptance and production hardening require separate evidence. See [release readiness](RELEASE_READINESS.md) and [security baseline](SECURITY_BASELINE.md).
