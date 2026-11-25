from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ThreatWeave API"
    app_env: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://detection_app:change-me-locally@localhost:5432/detection_assistant"
    redis_url: str = "redis://localhost:6379/0"
    cors_origins: str = "http://localhost:5173"
    llm_default_provider: str | None = "openai"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4.1-mini"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @property
    def allowed_origins(self) -> list[str]:
        configured = [item.strip() for item in self.cors_origins.split(",") if item.strip()]
        # The production frontend is hosted on GitHub Pages; keep it allowed even
        # when Render's CORS_ORIGINS environment variable contains other origins.
        production_frontend = "https://shikhasahu-23.github.io"
        if production_frontend not in configured:
            configured.append(production_frontend)
        return configured


@lru_cache
def get_settings() -> Settings:
    return Settings()
