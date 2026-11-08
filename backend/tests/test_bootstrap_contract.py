from app.config import Settings, settings
from app.main import app


def test_shared_settings_instance_is_exported_for_application_and_migrations():
    assert isinstance(settings, Settings)
    assert settings.environment == "development"


def test_fastapi_application_imports_with_shared_settings():
    assert app.title == "OpsAegis API"
    assert app.version


def test_development_configuration_remains_safe_for_ci():
    assert settings.database_url.startswith("sqlite:")
    assert settings.allowed_hosts
    assert settings.allowed_origins
