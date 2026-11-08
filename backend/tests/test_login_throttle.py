import pytest
from fastapi import HTTPException
from redis.exceptions import ConnectionError as RedisConnectionError

from app import login_throttle
from app.config import settings


class FakeRedis:
    def __init__(self, result):
        self.result = result
        self.eval_args = None
        self.closed = False

    def eval(self, *args):
        self.eval_args = args
        return self.result

    def close(self):
        self.closed = True


def test_login_throttle_uses_hashed_ip_and_email_and_closes_client(monkeypatch):
    fake = FakeRedis([2, 3, 60, 900])
    monkeypatch.setattr(login_throttle.Redis, "from_url", lambda *args, **kwargs: fake)
    login_throttle.enforce_login_rate_limit("203.0.113.10", "user@example.com")
    assert fake.closed
    assert fake.eval_args[1] == 2
    assert "203.0.113.10" not in fake.eval_args[2]
    assert "user@example.com" not in fake.eval_args[3]


def test_email_limit_returns_429_and_retry_after(monkeypatch):
    fake = FakeRedis([2, settings.auth_login_email_limit + 1, 60, 417])
    monkeypatch.setattr(login_throttle.Redis, "from_url", lambda *args, **kwargs: fake)
    with pytest.raises(HTTPException) as exc:
        login_throttle.enforce_login_rate_limit("203.0.113.10", "user@example.com")
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "417"


def test_ip_limit_returns_429(monkeypatch):
    fake = FakeRedis([settings.auth_login_ip_limit + 1, 1, 52, 900])
    monkeypatch.setattr(login_throttle.Redis, "from_url", lambda *args, **kwargs: fake)
    with pytest.raises(HTTPException) as exc:
        login_throttle.enforce_login_rate_limit("203.0.113.10", "user@example.com")
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "52"


def test_redis_unavailable_fails_closed(monkeypatch):
    class UnavailableRedis:
        @staticmethod
        def from_url(*args, **kwargs):
            raise RedisConnectionError("unavailable")
    monkeypatch.setattr(login_throttle, "Redis", UnavailableRedis)
    with pytest.raises(HTTPException) as exc:
        login_throttle.enforce_login_rate_limit("203.0.113.10", "user@example.com")
    assert exc.value.status_code == 503
    assert exc.value.headers["Retry-After"] == "5"
