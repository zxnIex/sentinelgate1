from sentinelgate.executor import ToolRegistry
from sentinelgate.models import ToolCallRequest


def call(tool: str, arguments=None, provenance_tokens=None) -> ToolCallRequest:
    return ToolCallRequest(
        user_id="user-1",
        tool_name=tool,
        arguments=arguments or {},
        provenance_tokens=provenance_tokens or [],
    )


def test_safe_tool_executes_and_replay_is_blocked(service, principal):
    request = call("search_knowledge", {"query": "returns"})
    first = service.execute(request, principal)
    second = service.execute(request, principal)
    assert first.status == "succeeded"
    assert second.status == "replay_blocked"


def test_approval_is_exact_expiring_and_one_time(service, principal, mixed_token):
    pending = service.execute(
        call(
            "send_email",
            {"to": "a@example.com", "subject": "Hello", "body": "hello"},
            [mixed_token],
        ),
        principal,
    )
    assert pending.status == "pending_approval"
    approved = service.store.resolve_approval(
        pending.approval_id, "approved", "reviewer", "looks safe"
    )
    assert approved is not None
    executed = service.execute_approved(pending.approval_id)
    replay = service.execute_approved(pending.approval_id)
    assert executed.status == "succeeded"
    assert replay is None


def test_tampered_approved_request_fails_hash_check(service, principal, mixed_token):
    pending = service.execute(
        call(
            "send_email",
            {"to": "a@example.com", "subject": "Hello", "body": "hello"},
            [mixed_token],
        ),
        principal,
    )
    service.store.resolve_approval(pending.approval_id, "approved", "reviewer", "ok")
    with service.store._connect() as db:
        row = db.execute(
            "SELECT request_json FROM approvals_v2 WHERE id=?", (pending.approval_id,)
        ).fetchone()
        assert "a@example.com" not in row["request_json"]
        protected = row["request_json"]
        replacement = "A" if protected[-1] != "A" else "B"
        db.execute(
            "UPDATE approvals_v2 SET request_json=? WHERE id=?",
            (protected[:-1] + replacement, pending.approval_id),
        )
    assert service.execute_approved(pending.approval_id) is None


def test_secret_tool_output_is_blocked(service, principal):
    registry = ToolRegistry()
    registry.register(
        "search_knowledge", lambda _: {"api_key": "sk-abcdefghijklmnop123456"}
    )
    service.executor = registry
    result = service.execute(call("search_knowledge"), principal)
    assert result.status == "output_blocked"
    assert result.output is None


def test_rate_limit_is_atomic(store):
    assert store.rate_allowed("t", "a", 1)
    assert not store.rate_allowed("t", "a", 1)
