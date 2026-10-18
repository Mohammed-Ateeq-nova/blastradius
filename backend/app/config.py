from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    falkordb_host: str = "127.0.0.1"
    falkordb_port: int = 6379
    falkordb_password: str | None = None
    falkordb_graph: str = "blast_radius"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"


settings = Settings()
