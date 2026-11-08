from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    environment: str = Field(default="development", validation_alias="OPS_AEGIS_ENV")
    secret_key: str = Field(default="development-only-change-this", validation_alias="OPS_AEGIS_SECRET_KEY")
    access_token_minutes: int = Field(default=15, validation_alias="OPS_AEGIS_ACCESS_TOKEN_MINUTES")
    database_url: str = Field(default="sqlite:///./opsaegis.db", validation_alias="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")
    cors_origins: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")
    wazuh_indexer_url: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_URL")
    wazuh_indexer_username: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_USERNAME")
    wazuh_indexer_password: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_PASSWORD")
    wazuh_indexer_index_pattern: str = Field(default="wazuh-alerts-*", validation_alias="WAZUH_INDEXER_INDEX_PATTERN")
    wazuh_indexer_verify_tls: bool = Field(default=True, validation_alias="WAZUH_INDEXER_VERIFY_TLS")
    wazuh_indexer_ca_cert: str | None = Field(default=None, validation_alias="WAZUH_INDEXER_CA_CERT")
    wazuh_indexer_timeout_seconds: int = Field(default=10, validation_alias="WAZUH_INDEXER_TIMEOUT_SECONDS")
    wazuh_indexer_max_results: int = Field(default=500, validation_alias="WAZUH_INDEXER_MAX_RESULTS")
    crowdsec_lapi_url: str | None = Field(default=None, validation_alias="CROWDSEC_LAPI_URL")
    crowdsec_api_key: str | None = Field(default=None, validation_alias="CROWDSEC_API_KEY")
    crowdsec_ca_cert: str | None = Field(default=None, validation_alias="CROWDSEC_CA_CERT")
    crowdsec_timeout_seconds: int = Field(default=10, validation_alias="CROWDSEC_TIMEOUT_SECONDS")
    crowdsec_max_results: int = Field(default=500, validation_alias="CROWDSEC_MAX_RESULTS")
    virustotal_api_key: str | None = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, validation_alias="ABUSEIPDB_API_KEY")
    threat_intel_timeout_seconds: int = Field(default=10, validation_alias="THREAT_INTEL_TIMEOUT_SECONDS")
    threat_intel_cache_ttl_seconds: int = Field(default=900, validation_alias="THREAT_INTEL_CACHE_TTL_SECONDS")
    nvd_api_key: str | None = Field(default=None, validation_alias="NVD_API_KEY")
    nvd_timeout_seconds: int = Field(default=10, validation_alias="NVD_TIMEOUT_SECONDS")
    nuclei_enabled: bool = Field(default=False, validation_alias="NUCLEI_ENABLED")
    nuclei_binary: str = Field(default="nuclei", validation_alias="NUCLEI_BINARY")
    nuclei_timeout_seconds: int = Field(default=600, validation_alias="NUCLEI_TIMEOUT_SECONDS")
    nuclei_max_output_bytes: int = Field(default=10485760, validation_alias="NUCLEI_MAX_OUTPUT_BYTES")
    nuclei_rate_limit: int = Field(default=5, validation_alias="NUCLEI_RATE_LIMIT")
    shannon_enabled: bool = Field(default=False, validation_alias="SHANNON_ENABLED")
    shannon_runner_url: str | None = Field(default=None, validation_alias="SHANNON_RUNNER_URL")
    shannon_runner_token: str | None = Field(default=None, validation_alias="SHANNON_RUNNER_TOKEN")
    shannon_timeout_seconds: int = Field(default=15, validation_alias="SHANNON_TIMEOUT_SECONDS")
    shannon_max_response_bytes: int = Field(default=5242880, validation_alias="SHANNON_MAX_RESPONSE_BYTES")
    shannon_max_findings: int = Field(default=200, validation_alias="SHANNON_MAX_FINDINGS")
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    @model_validator(mode="after")
    def validate_security_settings(self):
        if not 5 <= self.access_token_minutes <= 60:
            raise ValueError("OPS_AEGIS_ACCESS_TOKEN_MINUTES must be between 5 and 60")
        if self.environment.lower() == "production" and (len(self.secret_key) < 32 or self.secret_key == "development-only-change-this"):
            raise ValueError("Production requires a unique OPS_AEGIS_SECRET_KEY of at least 32 characters")
        for name, value in (("WAZUH_INDEXER_TIMEOUT_SECONDS", self.wazuh_indexer_timeout_seconds),
                            ("CROWDSEC_TIMEOUT_SECONDS", self.crowdsec_timeout_seconds)):
            if not 1 <= value <= 60: raise ValueError(f"{name} must be between 1 and 60")
        for name, value in (("WAZUH_INDEXER_MAX_RESULTS", self.wazuh_indexer_max_results),
                            ("CROWDSEC_MAX_RESULTS", self.crowdsec_max_results)):
            if not 1 <= value <= 1000: raise ValueError(f"{name} must be between 1 and 1000")
        if not 1 <= self.threat_intel_timeout_seconds <= 30: raise ValueError("THREAT_INTEL_TIMEOUT_SECONDS must be between 1 and 30")
        if not 60 <= self.threat_intel_cache_ttl_seconds <= 86400: raise ValueError("THREAT_INTEL_CACHE_TTL_SECONDS must be between 60 and 86400")
        if not 1 <= self.nvd_timeout_seconds <= 30: raise ValueError("NVD_TIMEOUT_SECONDS must be between 1 and 30")
        if not 30 <= self.nuclei_timeout_seconds <= 1800: raise ValueError("NUCLEI_TIMEOUT_SECONDS must be between 30 and 1800")
        if not 1048576 <= self.nuclei_max_output_bytes <= 52428800: raise ValueError("NUCLEI_MAX_OUTPUT_BYTES must be between 1 MiB and 50 MiB")
        if not 1 <= self.nuclei_rate_limit <= 20: raise ValueError("NUCLEI_RATE_LIMIT must be between 1 and 20")
        if not 5 <= self.shannon_timeout_seconds <= 60: raise ValueError("SHANNON_TIMEOUT_SECONDS must be between 5 and 60")
        if not 1048576 <= self.shannon_max_response_bytes <= 5242880: raise ValueError("SHANNON_MAX_RESPONSE_BYTES must be between 1 MiB and 5 MiB")
        if not 1 <= self.shannon_max_findings <= 500: raise ValueError("SHANNON_MAX_FINDINGS must be between 1 and 500")
        if self.shannon_enabled and (not self.shannon_runner_url or not self.shannon_runner_token):
            raise ValueError("SHANNON_ENABLED requires SHANNON_RUNNER_URL and SHANNON_RUNNER_TOKEN")
        if self.shannon_runner_url and not self.shannon_runner_url.startswith("https://"):
            raise ValueError("SHANNON_RUNNER_URL must use HTTPS")
        return self
    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]
settings = Settings()
