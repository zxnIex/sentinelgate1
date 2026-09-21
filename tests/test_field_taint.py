import json
from datetime import timedelta

import pytest

from sentinelgate.executor import demo_registry
from sentinelgate.identity import TokenSigner
from sentinelgate.models import (
    AgentPrincipal,
    DataClassification,
    Decision,
    DerivationInput,
    FieldDerivation,
    FieldProvenanceReference,
    StructuredProvenanceAttestRequest,
    StructuredProvenanceDeriveRequest,
    ToolCallRequest,
    TrustLevel,
    utc_now,
)
from sentinelgate.policy import PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store


def field_service(tmp_path):
    policy = {
        "version": "field-test-1",
        "defaults": {"requests_per_minute": 1000},
        "tools": {
            "send_email": {
                "risk": "high",
                "effect": "require_approval",
                "allowed_agents": ["research-agent"],
                "required_scopes": ["tools:email:send"],
                "sensitive": True,
                "requires_provenance": True,
                "egress": True,
                "field_policies": {
                    "/body": {
                        "requires_provenance": True,
                        "blocked_labels": ["customer-data", "secret"],
                        "max_classification": "internal",
                        "deny_untrusted": True,
                    }
                },
            }
        },
    }
    path = tmp_path / "field-policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    signer = TokenSigner("field-test-token-key-at-least-24", "field-test")
    provenance = ProvenanceService(signer)
    service = GatewayService(
        PolicyEngine(path),
        Store(tmp_path / "field.db", "audit", "field-encryption-key-at-least-24"),
        provenance,
        demo_registry(),
    )
    principal = AgentPrincipal(
        agent_id="research-agent",
        tenant_id="tenant",
        scopes=frozenset({"tools:email:send", "provenance:attest", "provenance:derive"}),
        token_id="field-test",
        expires_at=utc_now() + timedelta(hours=1),
    )
    return service, provenance, principal


def test_field_taint_blocks_only_bound_sensitive_body(tmp_path):
    service, provenance, principal = field_service(tmp_path)
    attestation = provenance.attest_structured(
        StructuredProvenanceAttestRequest(
            source_id="customer-api",
            value={"safe": "Weekly report", "secret": "account 123"},
            trust=TrustLevel.TRUSTED,
            field_overrides={
                "/secret": {
                    "trust": "untrusted",
                    "classification": "confidential",
                    "labels": ["customer-data"],
                }
            },
            trace_id="field-trace",
        ),
        principal.tenant_id,
    )
    call = ToolCallRequest(
        user_id="u",
        tool_name="send_email",
        arguments={
            "to": "security@example.com",
            "subject": "Weekly report",
            "body": "account 123",
        },
        trace_id="field-trace",
        field_provenance={
            "/body": [
                FieldProvenanceReference(
                    token=attestation.token, source_pointer="/secret"
                )
            ]
        },
    )
    result = service.evaluate(call, principal, side_effects=False)
    assert result.decision is Decision.DENY
    assert "FIELD_TAINT_LABEL:/body:customer-data" in result.reason_codes


def test_field_binding_cannot_be_reused_for_different_value(tmp_path):
    service, provenance, principal = field_service(tmp_path)
    attestation = provenance.attest_structured(
        StructuredProvenanceAttestRequest(
            source_id="source",
            value={"body": "original"},
            trust=TrustLevel.TRUSTED,
            trace_id="field-trace",
        ),
        principal.tenant_id,
    )
    call = ToolCallRequest(
        user_id="u",
        tool_name="send_email",
        arguments={"to": "a@example.com", "subject": "s", "body": "changed"},
        trace_id="field-trace",
        field_provenance={
            "/body": [
                FieldProvenanceReference(
                    token=attestation.token, source_pointer="/body"
                )
            ]
        },
    )
    result = service.evaluate(call, principal, side_effects=False)
    assert result.decision is Decision.DENY
    assert result.reason_codes == ["INVALID_PROVENANCE"]


def test_llm_derivation_conservatively_unions_every_input(tmp_path):
    _, provenance, principal = field_service(tmp_path)
    safe = provenance.attest_structured(
        StructuredProvenanceAttestRequest(
            source_id="safe", value={"text": "hello"}, trust=TrustLevel.TRUSTED,
            trace_id="derive-trace",
        ), principal.tenant_id,
    )
    secret = provenance.attest_structured(
        StructuredProvenanceAttestRequest(
            source_id="secret", value={"text": "customer 42"},
            classification=DataClassification.CONFIDENTIAL,
            labels=["customer-data"], trace_id="derive-trace",
        ), principal.tenant_id,
    )
    result = provenance.derive_structured(
        StructuredProvenanceDeriveRequest(
            source_id="model-output",
            value={"summary": "A summary", "title": "Safe-looking title"},
            inputs={
                "safe": DerivationInput(
                    value="hello",
                    reference=FieldProvenanceReference(
                        token=safe.token, source_pointer="/text"
                    ),
                ),
                "secret": DerivationInput(
                    value="customer 42",
                    reference=FieldProvenanceReference(
                        token=secret.token, source_pointer="/text"
                    ),
                ),
            },
            mode="llm",
            trace_id="derive-trace",
        ),
        principal.tenant_id,
    )
    assert set(result.field_taint) == {"/summary", "/title"}
    assert all("customer-data" in item.labels for item in result.field_taint.values())
    assert all(
        item.classification is DataClassification.CONFIDENTIAL
        for item in result.field_taint.values()
    )


def test_deterministic_derivation_is_verified(tmp_path):
    _, provenance, principal = field_service(tmp_path)
    source = provenance.attest_structured(
        StructuredProvenanceAttestRequest(
            source_id="source", value={"first": "A", "second": "B"},
            trace_id="derive-trace",
        ), principal.tenant_id,
    )
    inputs = {
        name: DerivationInput(
            value=value,
            reference=FieldProvenanceReference(
                token=source.token, source_pointer=f"/{name}"
            ),
        )
        for name, value in {"first": "A", "second": "B"}.items()
    }
    request = StructuredProvenanceDeriveRequest(
        source_id="concat",
        value={"body": "A-B"},
        inputs=inputs,
        derivations={
            "/body": FieldDerivation(
                operation="concat", inputs=["first", "second"], separator="-"
            )
        },
        mode="deterministic",
        trace_id="derive-trace",
    )
    result = provenance.derive_structured(request, principal.tenant_id)
    assert result.field_taint["/body"].content_digest
    with pytest.raises(ValueError, match="output mismatch"):
        provenance.derive_structured(
            request.model_copy(update={"value": {"body": "forged"}}),
            principal.tenant_id,
        )
