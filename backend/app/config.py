from urllib.parse import unquote, urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_PLACEHOLDER_SECRET_MARKERS = ("change-me", "changeme", "change_me", "placeholder", "your-secret", "your-password", "replace-me", "replace_me")


def _is_placeholder_secret(value: str) -> bool:
    normalized = value.strip().lower()
    return any(marker in normalized for marker in _PLACEHOLDER_SECRET_MARKERS)


class Settings(BaseSettings):
    environment: str = Field(default="development", validation_alias="OPS_AEGIS_ENV")
    secret_key: str = Field(default="development-only-change-this", validation_alias="OPS_AEGIS_SECRET_KEY")
    access_token_minutes: int = Field(default=15, validation_alias="OPS_AEGIS_ACCESS_TOKEN_MINUTES")
    auth_login_ip_limit: int = Field(default=30, validation_alias="AUTH_LOGIN_IP_LIMIT")
    auth_login_email_limit: int = Field(default=5, validation_alias="AUTH_LOGIN_EMAIL_LIMIT")
    auth_login_ip_window_seconds: int = Field(default=60, validation_alias="AUTH_LOGIN_IP_WINDOW_SECONDS")
    auth_login_email_window_seconds: int = Field(default=900, validation_alias="AUTH_LOGIN_EMAIL_WINDOW_SECONDS")
    database_url: str = Field(default="sqlite:///./opsaegis.db", validation_alias="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")
    cors_origins: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")
    allowed_hosts_raw: str = Field(default="localhost,127.0.0.1,testserver", validation_alias="OPS_AEGIS_ALLOWED_HOSTS")
    wazuh_manager_url: str | None = Field(default=None, validation_alias="WAZUH_MANAGER_URL")
    wazuh_manager_username: str | None = Field(default=None, validation_alias="WAZUH_MANAGER_USERNAME")
    wazuh_manager_password: str | None = Field(default=None, validation_alias="WAZUH_MANAGER_PASSWORD")
    wazuh_manager_ca_cert: str | None = Field(default=None, validation_alias="WAZUH_MANAGER_CA_CERT")
    wazuh_manager_timeout_seconds: int = Field(default=10, validation_alias="WAZUH_MANAGER_TIMEOUT_SECONDS")
    wazuh_manager_max_agents: int = Field(default=500, validation_alias="WAZUH_MANAGER_MAX_AGENTS")
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
        if not 1 <= self.auth_login_ip_limit <= 1000:
            raise ValueError("AUTH_LOGIN_IP_LIMIT must be between 1 and 1000")
        if not 1 <= self.auth_login_email_limit <= 100:
            raise ValueError("AUTH_LOGIN_EMAIL_LIMIT must be between 1 and 100")
        if not 10 <= self.auth_login_ip_window_seconds <= 3600:
            raise ValueError("AUTH_LOGIN_IP_WINDOW_SECONDS must be between 10 and 3600")
        if not 60 <= self.auth_login_email_window_seconds <= 86400:
            raise ValueError("AUTH_LOGIN_EMAIL_WINDOW_SECONDS must be between 60 and 86400")
        if not 5 <= self.access_token_minutes <= 60:
            raise ValueError("OPS_AEGIS_ACCESS_TOKEN_MINUTES must be between 5 and 60")
        hosts = self.allowed_hosts
        if not hosts:
            raise ValueError("OPS_AEGIS_ALLOWED_HOSTS must contain at least one host")
        for host in hosts:
            if host != host.strip() or "://" in host or "/" in host or "?" in host or "#" in host or ":" in host and not (host.startswith("[") and host.endswith("]")):
                raise ValueError("OPS_AEGIS_ALLOWED_HOSTS entries must be hostnames or IP addresses without ports or schemes")
            if host == "*" or host.startswith("*.") or host.lower() != host:
                raise ValueError("OPS_AEGIS_ALLOWED_HOSTS requires explicit lowercase hosts; wildcards are forbidden")
        if self.environment.lower() == "production":
            if len(self.secret_key) < 32 or self.secret_key == "development-only-change-this" or _is_placeholder_secret(self.secret_key) or len(set(self.secret_key)) < 12:
                raise ValueError("Production requires a unique OPS_AEGIS_SECRET_KEY of at least 32 characters")
            if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ValueError("Production requires PostgreSQL; SQLite is supported only for development and tests")
            database_parts = urlsplit(self.database_url)
            database_password = unquote(database_parts.password or "")
            if database_parts.hostname in {None, "localhost", "127.0.0.1", "::1"}:
                raise ValueError("Production DATABASE_URL must use a reachable non-loopback PostgreSQL host")
            if len(database_password) < 16 or database_password.lower() in {"password", "postgres"} or _is_placeholder_secret(database_password):
                raise ValueError("Production DATABASE_URL must contain a unique database password of at least 16 characters")
            redis_parts = urlsplit(self.redis_url)
            if redis_parts.scheme not in {"redis", "rediss"} or redis_parts.hostname in {None, "localhost", "127.0.0.1", "::1"}:
                raise ValueError("Production requires a reachable Redis service URL; loopback Redis is not allowed")
            redis_password = unquote(redis_parts.password or "")
            if len(redis_password) < 16 or redis_password.lower() in {"password", "redis"} or _is_placeholder_secret(redis_password):
                raise ValueError("Production REDIS_URL must contain a unique Redis password of at least 16 characters")
            origins = self.allowed_origins
            if not origins or "*" in origins:
                raise ValueError("Production CORS_ORIGINS must contain explicit HTTPS origins; wildcards are forbidden")
            for origin in origins:
                parsed = urlsplit(origin)
                if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
                    raise ValueError("Every production CORS_ORIGINS entry must be an HTTPS origin without a path")
                if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
                    raise ValueError("Production CORS_ORIGINS cannot use loopback hosts")
            if self.nuclei_enabled:
                raise ValueError("NUCLEI_ENABLED is blocked in production until scanning runs in an isolated worker")
        for name, value in (("WAZUH_MANAGER_TIMEOUT_SECONDS", self.wazuh_manager_timeout_seconds),
                            ("WAZUH_INDEXER_TIMEOUT_SECONDS", self.wazuh_indexer_timeout_seconds),
                            ("CROWDSEC_TIMEOUT_SECONDS", self.crowdsec_timeout_seconds)):
            if not 1 <= value <= 60:
                raise ValueError(f"{name} must be between 1 and 60")
        if not 1 <= self.wazuh_manager_max_agents <= 2000:
            raise ValueError("WAZUH_MANAGER_MAX_AGENTS must be between 1 and 2000")
        if self.wazuh_manager_url and not self.wazuh_manager_url.startswith("https://"):
            raise ValueError("WAZUH_MANAGER_URL must use HTTPS")
        for name, value in (("WAZUH_INDEXER_MAX_RESULTS", self.wazuh_indexer_max_results),
                            ("CROWDSEC_MAX_RESULTS", self.crowdsec_max_results)):
            if not 1 <= value <= 1000:
                raise ValueError(f"{name} must be between 1 and 1000")
        if not 1 <= self.threat_intel_timeout_seconds <= 30:
            raise ValueError("THREAT_INTEL_TIMEOUT_SECONDS must be between 1 and 30")
        if not 60 <= self.threat_intel_cache_ttl_seconds <= 86400:
            raise ValueError("THREAT_INTEL_CACHE_TTL_SECONDS must be between 60 and 86400")
        if not 1 <= self.nvd_timeout_seconds <= 30:
            raise ValueError("NVD_TIMEOUT_SECONDS must be between 1 and 30")
        if not 30 <= self.nuclei_timeout_seconds <= 1800:
            raise ValueError("NUCLEI_TIMEOUT_SECONDS must be between 30 and 1800")
        if not 1048576 <= self.nuclei_max_output_bytes <= 52428800:
            raise ValueError("NUCLEI_MAX_OUTPUT_BYTES must be between 1 MiB and 50 MiB")
        if not 1 <= self.nuclei_rate_limit <= 20:
            raise ValueError("NUCLEI_RATE_LIMIT must be between 1 and 20")
        if not 5 <= self.shannon_timeout_seconds <= 60:
            raise ValueError("SHANNON_TIMEOUT_SECONDS must be between 5 and 60")
        if not 1048576 <= self.shannon_max_response_bytes <= 5242880:
            raise ValueError("SHANNON_MAX_RESPONSE_BYTES must be between 1 MiB and 5 MiB")
        if not 1 <= self.shannon_max_findings <= 500:
            raise ValueError("SHANNON_MAX_FINDINGS must be between 1 and 500")
        if self.shannon_enabled and (not self.shannon_runner_url or not self.shannon_runner_token):
            raise ValueError("SHANNON_ENABLED requires SHANNON_RUNNER_URL and SHANNON_RUNNER_TOKEN")
        if self.shannon_runner_url and not self.shannon_runner_url.startswith("https://"):
            raise ValueError("SHANNON_RUNNER_URL must use HTTPS")
        return self

    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def allowed_hosts(self) -> list[str]:
        return [item.strip() for item in self.allowed_hosts_raw.split(",") if item.strip()]
