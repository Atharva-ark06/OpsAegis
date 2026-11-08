from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    environment: str = Field(default="development", validation_alias="OPS_AEGIS_ENV")
    secret_key: str = Field(default="development-only-change-this", validation_alias="OPS_AEGIS_SECRET_KEY")
    access_token_minutes: int = Field(default=15, validation_alias="OPS_AEGIS_ACCESS_TOKEN_MINUTES")
    database_url: str = Field(default="sqlite:///./opsaegis.db", validation_alias="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")
    cors_origins: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")

    # Wazuh Indexer credentials are backend-only environment settings. They are
    # intentionally not persisted in the database or returned by API endpoints.
    wazuh_indexer_url: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_URL")
    wazuh_indexer_username: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_USERNAME")
    wazuh_indexer_password: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_PASSWORD")
    wazuh_indexer_index_pattern: str = Field(default="wazuh-alerts-*", validation_alias="WAZUH_INDEXER_INDEX_PATTERN")
    wazuh_indexer_verify_tls: bool = Field(default=True, validation_alias="WAZUH_INDEXER_VERIFY_TLS")
    wazuh_indexer_ca_cert: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_CA_CERT")
    wazuh_indexer_timeout_seconds: int = Field(default=10, validation_alias="WAZUH_INDEXER_TIMEOUT_SECONDS")
    wazuh_indexer_max_results: int = Field(default=500, validation_alias="WAZUH_INDEXER_MAX_RESULTS")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def validate_security_settings(self):
        if self.access_token_minutes < 5 or self.access_token_minutes > 60:
            raise ValueError("OPS_AEGIS_ACCESS_TOKEN_MINUTES must be between 5 and 60")
        if self.environment.lower() == "production" and (
            len(self.secret_key) < 32 or self.secret_key == "development-only-change-this"
        ):
            raise ValueError("Production requires a unique OPS_AEGIS_SECRET_KEY of at least 32 characters")
        if not 1 <= self.wazuh_indexer_timeout_seconds <= 60:
            raise ValueError("WAZUH_INDEXER_TIMEOUT_SECONDS must be between 1 and 60")
        if not 1 <= self.wazuh_indexer_max_results <= 1000:
            raise ValueError("WAZUH_INDEXER_MAX_RESULTS must be between 1 and 1000")
        return self

    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

settings = Settings()
