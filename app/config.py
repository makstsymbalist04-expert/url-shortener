from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+asyncpg://shortener:shortener@localhost:5432/shortener"
    oauth_client_id: str = "swagger"
    oauth_redirect_uri: str = "http://localhost:8000/docs/oauth2-redirect"
    access_token_seconds: int = 3600
    secure_cookies: bool = False  # True when serving over HTTPS.


settings = Settings()
