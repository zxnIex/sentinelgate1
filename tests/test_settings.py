import pytest

from sentinelgate.settings import get_settings


def test_production_rejects_default_secrets(monkeypatch, tmp_path):
    # Keep a developer's real .env from leaking into this defaults-only test.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="strong"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_production_accepts_strong_distinct_secrets(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_AUDIT_SIGNING_KEY", "a" * 48)
    monkeypatch.setenv("SENTINEL_TOKEN_SIGNING_KEY", "b" * 48)
    monkeypatch.setenv("SENTINEL_DATA_ENCRYPTION_KEY", "c" * 48)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "d" * 48)
    get_settings.cache_clear()
    try:
        assert get_settings().environment == "production"
    finally:
        get_settings.cache_clear()


def test_production_rejects_partial_github_configuration(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_AUDIT_SIGNING_KEY", "a" * 48)
    monkeypatch.setenv("SENTINEL_TOKEN_SIGNING_KEY", "b" * 48)
    monkeypatch.setenv("SENTINEL_DATA_ENCRYPTION_KEY", "c" * 48)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "d" * 48)
    monkeypatch.setenv("SENTINEL_GITHUB_APP_ID", "123")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="GitHub App configuration"):
            get_settings()
    finally:
        get_settings.cache_clear()
