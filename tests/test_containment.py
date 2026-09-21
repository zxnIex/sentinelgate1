from sentinelgate.models import ContainmentMode, Decision, ToolCallRequest


def call(tool: str, arguments=None, **kwargs) -> ToolCallRequest:
    return ToolCallRequest(
        user_id="user-1", tool_name=tool, arguments=arguments or {}, **kwargs
    )


def test_restrict_containment_only_allows_named_tools(service, principal):
    record = service.store.contain_agent(
        principal.tenant_id,
        principal.agent_id,
        ContainmentMode.RESTRICT,
        "Investigating unusual behavior",
        "security@example.com",
        900,
        ["search_knowledge"],
        None,
    )
    allowed = service.evaluate(call("search_knowledge", {"query": "safe"}), principal)
    blocked = service.evaluate(call("send_email"), principal)
    assert allowed.decision is Decision.ALLOW
    assert blocked.decision is Decision.DENY
    assert "CONTAINMENT:TOOL_RESTRICTED" in blocked.reason_codes
    assert service.store.release_containment(record.id)


def test_quarantine_blocks_and_release_restores(service, principal):
    record = service.store.contain_agent(
        principal.tenant_id,
        principal.agent_id,
        ContainmentMode.QUARANTINE,
        "Credential theft signal",
        "security@example.com",
        900,
        [],
        None,
    )
    blocked = service.evaluate(call("search_knowledge", {"query": "safe"}), principal)
    assert blocked.decision is Decision.DENY
    assert "AGENT_QUARANTINED" in blocked.reason_codes
    assert service.store.release_containment(record.id)
    assert service.evaluate(
        call("search_knowledge", {"query": "safe"}), principal
    ).decision is Decision.ALLOW


def test_egress_volume_limit_denies_large_payload(service, principal, mixed_token):
    result = service.evaluate(
        call(
            "send_email",
            {"to": "a@example.com", "subject": "Report", "body": "x" * 100},
            provenance_tokens=[mixed_token],
        ),
        principal,
    )
    assert result.decision is Decision.DENY
    assert "EGRESS_SINGLE_LIMIT_EXCEEDED" in result.reason_codes


def test_registered_token_can_be_revoked_immediately(store, signer):
    issued = signer.issue_agent("agent-a", "tenant-a", ["tools:search"], 300)
    principal = signer.agent_principal(issued.access_token)
    store.register_agent_token(principal, "owner@example.com")
    assert store.token_is_active(principal)
    assert store.revoke_agent_tokens("tenant-a", "agent-a", "compromised") == 1
    assert not store.token_is_active(principal)


def test_sensitive_read_to_egress_sequence_is_detected(
    service, principal, mixed_token
):
    trace_id = "trace-sequence"
    service.store.record_action(
        principal.tenant_id,
        principal.agent_id,
        trace_id,
        "read_customer_record",
        "sensitive_read",
        "allow",
    )
    result = service.evaluate(
        call(
            "send_email",
            {"to": "a@example.com", "subject": "Report", "body": "short"},
            provenance_tokens=[mixed_token],
            trace_id=trace_id,
        ),
        principal,
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert "SUSPICIOUS_SEQUENCE:SENSITIVE_READ_TO_EGRESS" in result.reason_codes
