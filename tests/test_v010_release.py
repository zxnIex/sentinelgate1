import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from sentinelgate.api import (
    _decode_login_state,
    _encode_login_state,
    app,
    get_service,
    get_settings,
    get_store,
)
from sentinelgate.models import ToolCallRequest
from sentinelgate.postgres_backup import BackupError, restore_drill, verify_backup
from sentinelgate.settings import Settings
from sentinelgate.worker import DurableWorker


class RecordingNotifier:
    def __init__(self, succeeds=True):
        self.succeeds = succeeds
        self.calls = []

    def notify(self, approval, reasons):
        self.calls.append((approval.id, reasons))
        return self.succeeds


def _approval(service, principal, mixed_token):
    service.durable_notifications = True
    return service.execute(
        ToolCallRequest(
            user_id="u",
            tool_name="send_email",
            arguments={
                "to": "security@example.com",
                "subject": "Review",
                "body": "Bounded summary",
            },
            provenance_tokens=[mixed_token],
        ),
        principal,
    )


def test_durable_notification_survives_request_and_is_processed(
    service, store, principal, mixed_token
):
    result = _approval(service, principal, mixed_token)
    assert result.status == "pending_approval"
    assert store.list_outbox()[0]["status"] == "pending"

    notifier = RecordingNotifier()
    processed = DurableWorker(store, notifier, "worker-test").process_one()
    assert processed.completed is True
    assert notifier.calls[0][0] == result.approval_id
    assert store.list_outbox()[0]["status"] == "completed"
    assert store.worker_status()[0]["processed"] == 1


def test_outbox_is_deduplicated_and_failed_delivery_retries(store):
    first = store.enqueue_outbox("approval.required", "approval-1", {"approval_id": "missing"}, 1)
    second = store.enqueue_outbox("approval.required", "approval-1", {"approval_id": "changed"}, 1)
    assert first == second
    result = DurableWorker(store, RecordingNotifier(False), "worker-fail").process_one()
    assert result.claimed is True
    assert result.completed is False
    assert store.list_outbox()[0]["status"] == "dead"
    assert store.worker_status()[0]["failed"] == 1


def test_setup_system_and_assets_are_exposed(service, store):
    settings = Settings(admin_token="test-admin")
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_store] = lambda: store
    try:
        client = TestClient(app)
        headers = {"Authorization": "Bearer test-admin"}
        setup = client.get("/v1/setup/status", headers=headers)
        assert setup.status_code == 200
        assert setup.json()["ready_for_local_evaluation"] is True
        system = client.get("/v1/system/status", headers=headers)
        assert system.json()["database_backend"] == "sqlite"
        css = client.get("/assets/console.css")
        assert css.status_code == 200
        page = client.get("/console/onboarding")
        assert "script-src 'self'" in page.headers["content-security-policy"]
        assert "script-src 'unsafe-inline'" not in page.headers["content-security-policy"]
    finally:
        app.dependency_overrides.clear()


def test_backup_verification_checks_digest_and_catalog(monkeypatch, tmp_path):
    backup = tmp_path / "sentinelgate.dump"
    backup.write_bytes(b"postgres-backup")
    digest = hashlib.sha256(backup.read_bytes()).hexdigest()
    backup.with_suffix(".dump.manifest.json").write_text(
        json.dumps({"sha256": digest, "database": "sentinelgate"}), encoding="utf-8"
    )
    monkeypatch.setattr(
        "sentinelgate.postgres_backup.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="; header\n1; TABLE public agents\n"),
    )
    monkeypatch.setattr(
        "sentinelgate.postgres_backup._executable", lambda name: f"/usr/bin/{name}"
    )
    result = verify_backup(backup)
    assert result["verified"] is True
    assert result["catalog_entries"] == 1


def test_restore_drill_refuses_unbounded_database_name(tmp_path):
    with pytest.raises(BackupError, match="_restore_drill"):
        restore_drill(
            "postgresql://user:password@localhost/sentinelgate",
            tmp_path / "missing.dump",
            "sentinelgate",
        )


def test_oidc_login_state_is_signed_and_tampering_fails():
    payload = {"state": "state", "verifier": "verifier", "expires_at": 4_102_444_800}
    encoded = _encode_login_state(payload, "signing-key")
    assert _decode_login_state(encoded, "signing-key")["state"] == "state"
    with pytest.raises(Exception, match="OIDC login state"):
        _decode_login_state(encoded + "tampered", "signing-key")


def test_browser_oidc_login_uses_pkce_and_signed_state_cookie():
    settings = Settings(
        admin_auth_mode="oidc",
        oidc_issuer="https://identity.example",
        oidc_audience="sentinelgate",
        oidc_jwks_url="https://identity.example/jwks",
        oidc_authorization_endpoint="https://identity.example/authorize",
        oidc_token_endpoint="https://identity.example/token",
        oidc_client_id="sentinelgate-console",
        oidc_client_secret="client-secret",
    )
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        client = TestClient(app)
        response = client.get("/auth/login", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("https://identity.example/authorize?")
        assert "code_challenge_method=S256" in response.headers["location"]
        assert "sentinelgate_oidc_state=" in response.headers["set-cookie"]
        assert "HttpOnly" in response.headers["set-cookie"]
    finally:
        app.dependency_overrides.clear()
