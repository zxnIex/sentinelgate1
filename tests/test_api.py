from fastapi.testclient import TestClient

from sentinelgate.api import (
    app,
    get_provenance,
    get_service,
    get_signer,
    get_store,
    get_watch_service,
)
from sentinelgate.settings import Settings, get_settings
from sentinelgate.watch import WatchService


def test_authenticated_api_flow(service, signer, store):
    settings = Settings(
        admin_token="test-admin",
        token_signing_key="test-token-signing-key-at-least-24",
        audit_signing_key="test-audit-key",
        github_app_id=None,
        github_installation_id=None,
        github_private_key_path=None,
        github_allowed_repositories="",
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_signer] = lambda: signer
    app.dependency_overrides[get_provenance] = lambda: service.provenance
    try:
        client = TestClient(app)
        health = client.get("/health").json()
        assert health["version"] == "0.11.0"
        assert health["enforcement_mode"] == "enforce"
        schema = client.get("/openapi.json").json()
        schemes = schema["components"]["securitySchemes"]
        assert schemes["AdminBearer"]["scheme"] == "bearer"
        assert schemes["AgentBearer"]["scheme"] == "bearer"
        assert schema["paths"]["/v1/tokens/agents"]["post"]["security"] == [
            {"AdminBearer": []}
        ]
        assert schema["paths"]["/v1/execute"]["post"]["security"] == [
            {"AgentBearer": []}
        ]
        unauthenticated = client.post(
            "/v1/execute",
            json={"user_id": "u", "tool_name": "search_knowledge", "arguments": {}},
        )
        assert unauthenticated.status_code == 401

        token_response = client.post(
            "/v1/tokens/agents",
            headers={"Authorization": "Bearer test-admin"},
            json={
                "agent_id": "research-agent",
                "tenant_id": "tenant-1",
                "scopes": ["tools:search", "provenance:attest"],
                "ttl_seconds": 300,
            },
        )
        assert token_response.status_code == 200
        token = token_response.json()["access_token"]
        mcp_tools = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert [item["name"] for item in mcp_tools.json()["result"]["tools"]] == [
            "search_knowledge"
        ]
        trusted = client.post(
            "/v1/provenance/attest",
            headers={"Authorization": f"Bearer {token}"},
            json={"source_id": "web", "content": "safe", "trust": "trusted"},
        )
        assert trusted.status_code == 403
        mixed = client.post(
            "/v1/provenance/attest",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source_id": "web",
                "content": "external text",
                "trust": "mixed",
                "trace_id": "trace-api",
            },
        )
        assert mixed.status_code == 200
        executed = client.post(
            "/v1/execute",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "user_id": "u",
                "tool_name": "search_knowledge",
                "arguments": {"query": "policy"},
                "trace_id": "trace-api",
            },
        )
        assert executed.status_code == 200
        assert executed.json()["status"] == "succeeded"
        assert executed.json()["output_provenance_token"]
        forged_mcp_binding = client.post(
            "/v1/execute",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "user_id": "u",
                "tool_name": "search_knowledge",
                "arguments": {"query": "policy"},
                "mcp_server_id": "forged",
            },
        )
        assert forged_mcp_binding.status_code == 422
        traces = client.get(
            "/v1/traces", headers={"Authorization": "Bearer test-admin"}
        )
        assert traces.status_code == 200
        assert traces.json()[0]["trace_id"] == "trace-api"
        lineage = client.get(
            "/v1/traces/trace-api/lineage",
            headers={"Authorization": "Bearer test-admin"},
        )
        assert len(lineage.json()) == 2
        replay = client.post(
            "/v1/policy/replay",
            headers={"Authorization": "Bearer test-admin"},
            json={"limit": 10},
        )
        assert replay.status_code == 200
        assert replay.json()["evaluated"] >= 1
        connectors = client.get(
            "/v1/connectors", headers={"Authorization": "Bearer test-admin"}
        )
        assert connectors.status_code == 200
        assert connectors.json()[1]["status"] == "not_configured"
        assert connectors.json()[2]["name"] == "mcp_upstreams"

        agents = client.get(
            "/v1/agents", headers={"Authorization": "Bearer test-admin"}
        )
        assert agents.status_code == 200
        assert agents.json()[0]["owner"] == "platform-admin"
        revoked = client.post(
            "/v1/agents/tenant-1/research-agent/revoke",
            headers={"Authorization": "Bearer test-admin"},
            json={"reviewer": "security@example.com", "note": "test revocation"},
        )
        assert revoked.json()["revoked_tokens"] == 1
        after_revoke = client.post(
            "/v1/execute",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "user_id": "u",
                "tool_name": "search_knowledge",
                "arguments": {"query": "policy"},
            },
        )
        assert after_revoke.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_containment_api(service, store):
    settings = Settings(admin_token="test-admin")
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_store] = lambda: store
    try:
        client = TestClient(app)
        headers = {"Authorization": "Bearer test-admin"}
        invalid = client.post(
            "/v1/agents/t/a/contain",
            headers=headers,
            json={
                "mode": "restrict",
                "reviewer": "security@example.com",
                "reason": "investigation",
            },
        )
        assert invalid.status_code == 422
        created = client.post(
            "/v1/agents/t/a/contain",
            headers=headers,
            json={
                "mode": "quarantine",
                "reviewer": "security@example.com",
                "reason": "injection burst",
                "duration_seconds": 300,
            },
        )
        assert created.status_code == 200
        containment_id = created.json()["id"]
        assert client.get("/v1/containments", headers=headers).json()[0]["id"] == containment_id
        released = client.post(
            f"/v1/containments/{containment_id}/release",
            headers=headers,
            json={"reviewer": "security@example.com", "note": "cleared"},
        )
        assert released.json() == {"released": True}
    finally:
        app.dependency_overrides.clear()


def test_watch_api_is_scoped_and_monitor_only(service, signer, store):
    settings = Settings(
        admin_token="test-admin",
        token_signing_key="test-token-signing-key-at-least-24",
        audit_signing_key="test-audit-key",
    )
    watch = WatchService(store, monitor_only=True)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_signer] = lambda: signer
    app.dependency_overrides[get_watch_service] = lambda: watch
    try:
        client = TestClient(app)
        issued = client.post(
            "/v1/tokens/agents",
            headers={"Authorization": "Bearer test-admin"},
            json={
                "agent_id": "research-agent",
                "tenant_id": "tenant-1",
                "scopes": ["watch:write"],
                "ttl_seconds": 300,
            },
        )
        token = issued.json()["access_token"]
        agent_headers = {"Authorization": f"Bearer {token}"}
        task = client.post(
            "/v1/watch/tasks",
            headers=agent_headers,
            json={
                "task_id": "api-watch-task",
                "description": "Observe a bounded task",
                "profile": "strict",
            },
        )
        assert task.status_code == 200
        findings = []
        for _ in range(4):
            event = client.post(
                "/v1/watch/events",
                headers=agent_headers,
                json={
                    "task_id": "api-watch-task",
                    "event_type": "tool_call",
                    "tool_name": "check_status",
                    "call_fingerprint": "a" * 64,
                    "outcome": "allow",
                },
            )
            assert event.status_code == 200
            assert event.json()["monitor_only"] is True
            findings = event.json()["findings"]
        assert "WATCH_REPEATED_CALL" in {item["code"] for item in findings}

        admin_headers = {"Authorization": "Bearer test-admin"}
        summary = client.get("/v1/watch/summary", headers=admin_headers)
        assert summary.status_code == 200
        assert summary.json()["open_findings"] >= 1
        assert client.get("/v1/watch/tasks", headers=admin_headers).json()[0][
            "task_id"
        ] == "api-watch-task"
        assert len(
            client.get(
                "/v1/watch/tasks/api-watch-task/events", headers=admin_headers
            ).json()
        ) == 4
        assert store.list_containments() == []
    finally:
        app.dependency_overrides.clear()
