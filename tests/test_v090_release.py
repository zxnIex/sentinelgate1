import json
from pathlib import Path

import httpx
import pytest

from sentinelgate.adversarial_evaluation import run as run_adversarial
from sentinelgate.client import SentinelGateClient
from sentinelgate.settings import get_settings
from sentinelgate.storage import _PostgresConnection


class RecordingConnection:
    def __init__(self):
        self.calls = []

    def execute(self, statement, parameters=()):
        self.calls.append((statement, parameters))
        return self


def test_postgres_adapter_converts_placeholders_and_scripts():
    raw = RecordingConnection()
    connection = _PostgresConnection(raw)
    connection.execute("SELECT * FROM agents WHERE tenant_id=? AND agent_id=?", ("t", "a"))
    connection.executescript("CREATE TABLE one (id TEXT); CREATE TABLE two (id TEXT);")
    assert raw.calls[0][0].count("%s") == 2
    assert len(raw.calls) == 3


def test_production_requires_postgres(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_ADMIN_AUTH_MODE", "oidc")
    monkeypatch.setenv("SENTINEL_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SENTINEL_OIDC_AUDIENCE", "sentinelgate")
    monkeypatch.setenv("SENTINEL_OIDC_JWKS_URL", "https://issuer.example/jwks")
    for name, value in {
        "SENTINEL_AUDIT_SIGNING_KEY": "a" * 40,
        "SENTINEL_TOKEN_SIGNING_KEY": "b" * 40,
        "SENTINEL_DATA_ENCRYPTION_KEY": "c" * 40,
        "SENTINEL_ADMIN_TOKEN": "d" * 40,
    }.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="PostgreSQL"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_secret_files_override_environment_values(monkeypatch, tmp_path):
    secret = tmp_path / "audit-key"
    secret.write_text("f" * 40 + "\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_AUDIT_SIGNING_KEY_FILE", str(secret))
    get_settings.cache_clear()
    try:
        assert get_settings().audit_signing_key == "f" * 40
    finally:
        get_settings.cache_clear()


def test_adversarial_corpus_expands_to_one_hundred_cases():
    report = run_adversarial()
    assert report["cases"] == 100
    assert report["attack_cases"] == 80
    assert report["benign_cases"] == 20
    assert report["scope"] == "project-authored adversarial probes; not independent validation"
    assert isinstance(report["misses"], list)


def test_client_sends_field_provenance():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"decision": "deny"})

    client = SentinelGateClient(
        "https://sentinelgate.test",
        "agent-token",
        transport=httpx.MockTransport(handler),
    )
    client.evaluate(
        user_id="u",
        tool_name="send_email",
        arguments={"body": "x"},
        field_provenance={"/body": [{"token": "signed", "source_pointer": "/body"}]},
    )
    assert captured["field_provenance"]["/body"][0]["token"] == "signed"


def test_compose_defines_postgres_service():
    compose = (Path(__file__).resolve().parents[1] / "compose.yaml").read_text(encoding="utf-8")
    assert "postgres:17-alpine" in compose
    assert "SENTINEL_DATABASE_URL" in compose
