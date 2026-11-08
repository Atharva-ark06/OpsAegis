import pytest
from pydantic import ValidationError

from app.config import Settings


def production_settings(**overrides):
    values = {
        "OPS_AEGIS_ENV": "production",
        "OPS_AEGIS_SECRET_KEY": "a" * 48,
        "DATABASE_URL": "postgresql+psycopg://opsaegis:strong-password@postgres:5432/opsaegis",
        "REDIS_URL": "redis://redis:6379/0",
        "CORS_ORIGINS": "https://soc.example.com",
        "NUCLEI_ENABLED": "false",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_valid_production_configuration_is_accepted():
    settings = production_settings()
    assert settings.environment == "production"
    assert settings.allowed_origins == ["https://soc.example.com"]


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"OPS_AEGIS_SECRET_KEY": "development-only-change-this"}, "OPS_AEGIS_SECRET_KEY"),
        ({"OPS_AEGIS_SECRET_KEY": "short"}, "OPS_AEGIS_SECRET_KEY"),
        ({"DATABASE_URL": "sqlite:///./opsaegis.db"}, "PostgreSQL"),
        ({"REDIS_URL": "redis://localhost:6379/0"}, "loopback Redis"),
        ({"CORS_ORIGINS": "*"}, "wildcards are forbidden"),
        ({"CORS_ORIGINS": "http://soc.example.com"}, "HTTPS origin"),
        ({"CORS_ORIGINS": "https://localhost:5173"}, "loopback hosts"),
        ({"CORS_ORIGINS": "https://soc.example.com/app"}, "without a path"),
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
