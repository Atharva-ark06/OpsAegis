# API perimeter security

## Host-header validation

OpsAegis validates the HTTP Host header with Starlette TrustedHostMiddleware. This is independent of CORS: CORS controls browser cross-origin access and is not a Host-header validation mechanism.

Configure `OPS_AEGIS_ALLOWED_HOSTS` as a comma-separated list of exact lowercase hostnames or IP addresses, without schemes or ports. Wildcards are rejected. In production, include the public DNS name used by the reverse proxy and `127.0.0.1` for the container-local API health check. Do not add arbitrary internal or public hosts. The development default is limited to localhost, loopback and the test client hostname.

The production API container is not directly published to the host; the reverse proxy should preserve the intended public Host header. Do not trust arbitrary forwarded host/protocol headers. Configure proxy behavior only for a known, controlled proxy.

## Response headers

The API adds:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- restrictive `Permissions-Policy`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`

Authentication routes additionally return `Cache-Control: no-store` and `Pragma: no-cache` so token-bearing login responses and authentication metadata are not stored by compliant caches.

Public TLS termination and HSTS remain responsibilities of the external TLS reverse proxy. The API does not infer HTTPS from untrusted forwarded headers or emit HSTS based only on an environment flag.
