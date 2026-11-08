from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    environment: str = Field(default="development", validation_alias="OPS_AEGIS_ENV")
    secret_key: str = Field(default="development-only-change-this", validation_alias="OPS_AEGIS_SECRET_KEY")
    access_token_minutes: int = Field(default=15, validation_alias="OPS_AEGIS_ACCESS_TOKEN_MINUTES")
    database_url: str = Field(default="sqlite:///./opsaegis.db", validation_alias="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")
    cors_origins: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def validate_security_settings(self):
        if self.access_token_minutes < 5 or self.access_token_minutes > 60:
            raise ValueError("OPS_AEGIS_ACCESS_TOKEN_MINUTES must be between 5 and 60")
        if self.environment.lower() == "production" and (
            len(self.secret_key) < 32 or self.secret_key == "development-only-change-this"
        ):
            raise ValueError("Production requires a unique OPS_AEGIS_SECRET_KEY of at least 32 characters")
        return self

    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

settings = Settings()
