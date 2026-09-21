from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelgate.models import EnforcementMode


class Settings(BaseSettings):
    database_path: Path = Path("./data/sentinelgate.db")
    database_url: str | None = None
    database_pool_min_size: int = 1
    database_pool_max_size: int = 10
    worker_poll_interval_seconds: float = 1.0
    worker_lease_seconds: int = 30
    worker_max_attempts: int = 8
    worker_id: str | None = None
    policy_path: Path = Path("./config/policies.json")
    knowledge_path: Path = Path("./knowledge")
    mcp_upstreams_path: Path = Path("./config/mcp_upstreams.json")
    evidence_path: Path = Path("./evidence")
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    github_app_id: str | None = None
    github_installation_id: int | None = None
    github_private_key_path: Path | None = None
    github_allowed_repositories: str = ""
    approval_webhook_url: str | None = None
    approval_webhook_secret: str = "development-approval-webhook-key"
    approval_webhook_secret_file: Path | None = None
    console_public_url: str = "http://127.0.0.1:8000"
    audit_signing_key: str = "development-only-change-me"
    audit_signing_key_file: Path | None = None
    token_signing_key: str = "development-token-key-change-me"
    token_signing_key_file: Path | None = None
    data_encryption_key: str = "development-encryption-key-change-me"
    data_encryption_key_file: Path | None = None
    admin_token: str = "development-admin-token"
    admin_token_file: Path | None = None
    environment: str = "development"
    issuer: str = "https://sentinelgate.local"
    openai_api_key: str | None = None
    openai_model: str = "gpt-5.6-terra"
    declassification_allowed_labels: str = "reviewed,false-positive"
    admin_auth_mode: str = "shared"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_client_secret_file: Path | None = None
    oidc_scopes: str = "openid profile email"
    oidc_role_claim: str = "roles"
    oidc_admin_roles: str = "sentinelgate-admin,administrator"
    oidc_approver_roles: str = "sentinelgate-approver"
    oidc_analyst_roles: str = "sentinelgate-analyst"
    oidc_viewer_roles: str = "sentinelgate-viewer"

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="SENTINEL_", extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    file_secrets = {
        "audit_signing_key": settings.audit_signing_key_file,
        "token_signing_key": settings.token_signing_key_file,
        "data_encryption_key": settings.data_encryption_key_file,
        "admin_token": settings.admin_token_file,
        "approval_webhook_secret": settings.approval_webhook_secret_file,
        "oidc_client_secret": settings.oidc_client_secret_file,
    }
    resolved: dict[str, str] = {}
    for field, path in file_secrets.items():
        if path is not None:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RuntimeError(f"Unable to read configured secret file for {field}") from exc
            if not value:
                raise RuntimeError(f"Configured secret file for {field} is empty")
            resolved[field] = value
    if resolved:
        settings = settings.model_copy(update=resolved)
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
        if settings.admin_auth_mode not in {"oidc", "hybrid"}:
            raise RuntimeError("Production requires OIDC administrator authentication")
        if not all(
            (settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url)
        ):
            raise RuntimeError("Production OIDC configuration is incomplete")
        browser_oidc = (
            settings.oidc_authorization_endpoint,
            settings.oidc_token_endpoint,
            settings.oidc_client_id,
            settings.oidc_client_secret,
        )
        if any(browser_oidc) and not all(browser_oidc):
            raise RuntimeError("Browser OIDC sign-in configuration is incomplete")
        if any(
            value and not value.startswith("https://")
            for value in (
                settings.oidc_authorization_endpoint,
                settings.oidc_token_endpoint,
            )
        ):
            raise RuntimeError("Production OIDC endpoints must use HTTPS")
        if not settings.console_public_url.startswith("https://"):
            raise RuntimeError("Production console public URL must use HTTPS")
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
        if not settings.database_url or not settings.database_url.startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            raise RuntimeError("Production requires a PostgreSQL SENTINEL_DATABASE_URL")
        if settings.database_pool_min_size < 1 or (
            settings.database_pool_max_size < settings.database_pool_min_size
        ):
            raise RuntimeError("Invalid production database pool sizing")
        if settings.worker_poll_interval_seconds <= 0:
            raise RuntimeError("Worker poll interval must be positive")
        if settings.worker_lease_seconds < 10 or settings.worker_max_attempts < 1:
            raise RuntimeError("Invalid durable worker configuration")
    return settings
