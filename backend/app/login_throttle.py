"""Distributed login throttling backed by the shared Redis service."""
import hashlib
import hmac

from fastapi import HTTPException
from redis import Redis
from redis.exceptions import RedisError

from app.config import settings

_LOGIN_COUNTER_SCRIPT = """
local ip_count = redis.call('INCR', KEYS[1])
if ip_count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local email_count = redis.call('INCR', KEYS[2])
if email_count == 1 then redis.call('EXPIRE', KEYS[2], ARGV[2]) end
return {ip_count, email_count, redis.call('TTL', KEYS[1]), redis.call('TTL', KEYS[2])}
"""


def _key_digest(value: str) -> str:
    return hmac.new(
        settings.secret_key.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def enforce_login_rate_limit(client_ip: str, normalized_email: str) -> None:
    """Limit by source IP and account identifier without storing raw identifiers in Redis."""
    ip_key = f"opsaegis:auth:login:ip:{_key_digest(client_ip)}"
    email_key = f"opsaegis:auth:login:email:{_key_digest(normalized_email)}"
    client = None
    try:
        client = Redis.from_url(
            settings.redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )
        counts = client.eval(
            _LOGIN_COUNTER_SCRIPT,
            2,
            ip_key,
            email_key,
            settings.auth_login_ip_window_seconds,
            settings.auth_login_email_window_seconds,
        )
    except RedisError:
        # Authentication must not silently become unthrottled if Redis is unavailable.
        raise HTTPException(
            status_code=503,
            detail="Authentication temporarily unavailable; retry shortly",
            headers={"Retry-After": "5"},
        ) from None
    finally:
        if client is not None:
            try:
                client.close()
            except RedisError:
                pass

    ip_count, email_count, ip_ttl, email_ttl = (int(value) for value in counts)
    if ip_count > settings.auth_login_ip_limit or email_count > settings.auth_login_email_limit:
        retry_after = max(
            ip_ttl if ip_count > settings.auth_login_ip_limit else 0,
            email_ttl if email_count > settings.auth_login_email_limit else 0,
            1,
        )
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts; retry after the rate-limit window",
            headers={"Retry-After": str(retry_after)},
        )
