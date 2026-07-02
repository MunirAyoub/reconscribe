"""Settings, loaded from environment / .env (see .env.example)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    anthropic_api_key: str = ""
    # RECONSCRIBE_MODEL in the env; claude-sonnet-5 is the current Sonnet.
    reconscribe_model: str = "claude-sonnet-5"
    # Seconds between outbound requests to a target (be polite).
    reconscribe_request_delay: float = 0.5

    # A short, honest User-Agent so targets can see who's probing them.
    user_agent: str = "ReconScribe/0.1 (+passive-recon; https://github.com/MunirAyoub)"


settings = Settings()
