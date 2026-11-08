# Authentication security controls

## Login throttling

The login endpoint uses the shared Redis service for distributed fixed-window counters. Each attempt increments both a source-IP bucket and a normalized-account bucket in one Redis Lua operation. Default limits are 30 attempts per IP per 60 seconds and 5 attempts per account per 900 seconds.

The identifiers are HMAC-SHA256 digests keyed with the application signing secret; raw IP addresses and email addresses are not used as Redis key material. The API reads the direct ASGI client address and does not trust caller-supplied `X-Forwarded-For` headers. Configure the reverse proxy so the ASGI server receives the correct peer address; do not enable proxy-header trust for arbitrary clients.

If Redis is unavailable, login fails closed with HTTP 503 rather than silently disabling throttling. A limit breach returns HTTP 429 and a `Retry-After` header. Tune the limits for the deployment's NAT/user population:

- `AUTH_LOGIN_IP_LIMIT` (default 30, range 1–1000)
- `AUTH_LOGIN_EMAIL_LIMIT` (default 5, range 1–100)
- `AUTH_LOGIN_IP_WINDOW_SECONDS` (default 60, range 10–3600)
- `AUTH_LOGIN_EMAIL_WINDOW_SECONDS` (default 900, range 60–86400)

## Access tokens

Access tokens are HS256-signed and now require `sub`, `iat`, `exp`, `iss`, `aud`, `typ` and `jti` claims. The issuer is `opsaegis-api`, audience is `opsaegis`, and token type is `access`. Algorithm selection is fixed in server code. Authorization roles are loaded from the current user row on every request; token role claims are not trusted.

Tokens remain short-lived according to `OPS_AEGIS_ACCESS_TOKEN_MINUTES` (5–60 minutes). This change does not add refresh tokens or server-side token revocation; clearing a browser session does not invalidate a copied token before expiry. Rotate `OPS_AEGIS_SECRET_KEY` to invalidate all currently issued tokens.

## Login responses and audit

Unknown accounts execute the same password-hash verification path as known accounts to reduce timing-based account enumeration. Unknown, inactive and incorrect-password attempts share the same HTTP 401 response. Failed attempts create an audit record without storing the submitted email, password, or raw source IP.

## Operational notes

- Redis is a required authentication dependency for login throttling. Monitor Redis readiness and login 503/429 rates.
- The throttler uses fixed windows, not a sliding window. A caller can make requests near both sides of a window boundary.
- IP limits apply to the peer address observed by the API. Behind a reverse proxy, configure trusted proxy handling at the server/network boundary, not by accepting arbitrary forwarded headers.
- The application still requires TLS termination, secure browser deployment, secret rotation and external monitoring as described in the production deployment guide.
