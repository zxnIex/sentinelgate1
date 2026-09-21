from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelgate.models import EnforcementMode


class Settings(BaseSettings):
    database_path: Path = Path("./data/sentinelgate.db")
    policy_path: Path = Path("./config/policies.json")
    knowledge_path: Path = Path("./knowledge")
    mcp_upstreams_path: Path = Path("./config/mcp_upstreams.json")
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    github_app_id: str | None = None
    github_installation_id: int | None = None
    github_private_key_path: Path | None = None
    github_allowed_repositories: str = ""
    approval_webhook_url: str | None = None
    approval_webhook_secret: str = "development-approval-webhook-key"
    console_public_url: str = "http://127.0.0.1:8000"
    audit_signing_key: str = "development-only-change-me"
    token_signing_key: str = "development-token-key-change-me"
    data_encryption_key: str = "development-encryption-key-change-me"
    admin_token: str = "development-admin-token"
    environment: str = "development"
    issuer: str = "https://sentinelgate.local"
    openai_api_key: str | None = None
    openai_model: str = "gpt-5.6-terra"

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="SENTINEL_", extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.environment.casefold() == "production":
        configured = [
            settings.audit_signing_key,
            settings.token_signing_key,
            settings.data_encryption_key,
            settings.admin_token,
        ]
        if any(
            len(secret) < 32 or secret.startswith(("development-", "replace-with-"))
            for secret in configured
        ):
            raise RuntimeError("Production requires four strong, non-example secrets")
        if len(set(configured)) != len(configured):
            raise RuntimeError("Production secrets must be distinct")
        if settings.approval_webhook_url and (
            len(settings.approval_webhook_secret) < 32
            or settings.approval_webhook_secret.startswith(
                ("development-", "replace-with-")
            )
        ):
            raise RuntimeError("Production approval webhook requires a strong secret")
        github_values = (
            settings.github_app_id,
            settings.github_installation_id,
            settings.github_private_key_path,
            settings.github_allowed_repositories.strip(),
        )
        if any(github_values) and not all(github_values):
            raise RuntimeError(
                "Production GitHub App configuration and repository allowlist must be complete"
            )
        if settings.github_private_key_path and not settings.github_private_key_path.is_file():
            raise RuntimeError("Production GitHub App private key file does not exist")
    return settings
