from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    warden_env: str = "development"
    warden_api_token: SecretStr = SecretStr("")
    warden_identity_pepper: SecretStr = SecretStr("")
    warden_database_url: SecretStr = SecretStr(
        "postgresql://warden_app:local_app_only_change_me@localhost:5432/warden"
    )
    warden_migration_database_url: SecretStr = SecretStr("")
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "alaira-warden"

    # Optional connector secrets. Presence is not a verified connection.
    warden_github_token: SecretStr = SecretStr("")
    warden_nvd_api_key: SecretStr = SecretStr("")
    warden_meterless_api_key: SecretStr = SecretStr("")
    warden_meterless_base_url: str = ""
    warden_nvidia_api_key: SecretStr = SecretStr("")
    warden_nvidia_base_url: str = ""
    warden_grok_api_key: SecretStr = SecretStr("")
    warden_zetaris_api_key: SecretStr = SecretStr("")
    warden_zetaris_base_url: str = ""
    warden_zetaris_org_id: str = ""
    warden_zetaris_username: str = ""
    warden_zetaris_password: SecretStr = SecretStr("")
    warden_nvidia_model: str = ""
    warden_meterless_model: str = ""
    warden_model_dispatch_policy: str = "deny"
    warden_data_mode: Literal["local", "zetaris"] = "local"
    warden_zetaris_inventory_table: str = ""
    warden_zetaris_evidence_table: str = ""
    warden_cursor_api_key: SecretStr = SecretStr("")


@lru_cache
def get_settings() -> Settings:
    return Settings()
