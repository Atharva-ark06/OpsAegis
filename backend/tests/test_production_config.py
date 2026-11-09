import pytest
from pydantic import ValidationError

from app.config import Settings


def production_settings(**overrides):
    values = {
        "OPS_AEGIS_ENV": "production",
        "OPS_AEGIS_SECRET_KEY": "OpsAegis-production-signing-key-2026-unique!",
        "DATABASE_URL": "postgresql+psycopg://opsaegis:strong-password-123@postgres:5432/opsaegis",
        "REDIS_URL": "redis://:unique-redis-password-2026@redis:6379/0",
        "CORS_ORIGINS": "https://soc.example.com",
        "OPS_AEGIS_ALLOWED_HOSTS": "soc.example.com,127.0.0.1",
        "NUCLEI_ENABLED": "false",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_valid_production_configuration_is_accepted():
    settings = production_settings()
    assert settings.environment == "production"
    assert settings.allowed_origins == ["https://soc.example.com"]
    assert settings.allowed_hosts == ["soc.example.com", "127.0.0.1"]


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"OPS_AEGIS_SECRET_KEY": "development-only-change-this"}, "OPS_AEGIS_SECRET_KEY"),
        ({"OPS_AEGIS_SECRET_KEY": "development-only-change-this-secret-key-not-for-production"}, "OPS_AEGIS_SECRET_KEY"),
        ({"OPS_AEGIS_SECRET_KEY": "short"}, "OPS_AEGIS_SECRET_KEY"),
        ({"OPS_AEGIS_SECRET_KEY": "a" * 48}, "OPS_AEGIS_SECRET_KEY"),
        ({"OPS_AEGIS_SECRET_KEY": "CHANGE_ME_GENERATE_WITH_PYTHON_SECRETS_123456"}, "OPS_AEGIS_SECRET_KEY"),
        ({"DATABASE_URL": "postgresql+psycopg://opsaegis:strong-password-123@localhost:5432/opsaegis"}, "non-loopback PostgreSQL host"),
        ({"DATABASE_URL": "postgresql+psycopg://opsaegis:CHANGE_ME_USE_UNIQUE_URL_SAFE_PASSWORD@postgres:5432/opsaegis"}, "unique database password"),
        ({"REDIS_URL": "redis://redis:6379/0"}, "unique Redis password"),
        ({"REDIS_URL": "redis://:short@redis:6379/0"}, "unique Redis password"),
        ({"REDIS_URL": "redis://:CHANGE_ME_USE_UNIQUE_URL_SAFE_PASSWORD@redis:6379/0"}, "unique Redis password"),
        ({"REDIS_URL": "redis://:change-me-change-me@redis:6379/0"}, "unique Redis password"),
        ({"REDIS_URL": "redis://:unique-redis-password-2026@localhost:6379/0"}, "loopback Redis"),
        ({"DATABASE_URL": "sqlite:///./opsaegis.db"}, "PostgreSQL"),
        ({"DATABASE_URL": "postgresql+psycopg://opsaegis:change-me@postgres:5432/opsaegis"}, "database password"),
        ({"REDIS_URL": "redis://localhost:6379/0"}, "loopback Redis"),
        ({"CORS_ORIGINS": "*"}, "wildcards are forbidden"),
        ({"CORS_ORIGINS": "http://soc.example.com"}, "HTTPS origin"),
        ({"CORS_ORIGINS": "https://localhost:5173"}, "loopback hosts"),
        ({"CORS_ORIGINS": "https://soc.example.com/app"}, "without a path"),
        ({"OPS_AEGIS_ALLOWED_HOSTS": "*"}, "wildcards are forbidden"),
        ({"OPS_AEGIS_ALLOWED_HOSTS": "*.example.com"}, "wildcards are forbidden"),
        ({"OPS_AEGIS_ALLOWED_HOSTS": "https://soc.example.com"}, "hostnames or IP addresses"),
        ({"OPS_AEGIS_ALLOWED_HOSTS": "soc.example.com:443"}, "hostnames or IP addresses"),
        ({"OPS_AEGIS_ALLOWED_HOSTS": ""}, "at least one host"),
        ({"NUCLEI_ENABLED": "true"}, "isolated worker"),
    ],
)
def test_unsafe_production_configuration_is_rejected(override, message):
    with pytest.raises(ValidationError, match=message):
        production_settings(**override)


def test_development_keeps_local_sqlite_and_loopback_defaults():
    settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.database_url.startswith("sqlite:")
    assert settings.allowed_origins == ["http://localhost:5173"]
    assert settings.allowed_hosts == ["localhost", "127.0.0.1", "testserver"]


def test_url_encoded_database_and_redis_passwords_are_validated_after_decoding():
    settings = production_settings(
        DATABASE_URL="postgresql+psycopg://opsaegis:strong%2Dpassword%2D123@postgres:5432/opsaegis",
        REDIS_URL="redis://:unique%2Dredis%2Dpassword%2D2026@redis:6379/0",
    )
    assert settings.environment == "production"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"AUTH_LOGIN_IP_LIMIT": "0"}, "AUTH_LOGIN_IP_LIMIT"),
        ({"AUTH_LOGIN_EMAIL_LIMIT": "101"}, "AUTH_LOGIN_EMAIL_LIMIT"),
        ({"AUTH_LOGIN_IP_WINDOW_SECONDS": "5"}, "AUTH_LOGIN_IP_WINDOW_SECONDS"),
        ({"AUTH_LOGIN_EMAIL_WINDOW_SECONDS": "86401"}, "AUTH_LOGIN_EMAIL_WINDOW_SECONDS"),
    ],
)
def test_invalid_login_throttle_configuration_is_rejected(override, message):
    with pytest.raises(ValidationError, match=message):
        production_settings(**override)
