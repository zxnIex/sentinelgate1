import json
from datetime import timedelta
from pathlib import Path

import pytest

from sentinelgate.executor import demo_registry
from sentinelgate.identity import TokenSigner
from sentinelgate.models import (
    AgentPrincipal,
    ProvenanceAttestRequest,
    TrustLevel,
    utc_now,
)
from sentinelgate.policy import PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policies.json"
    path.write_text(
        json.dumps(
            {
                "version": "test-2",
                "defaults": {
                    "max_string_length": 100,
                    "requests_per_minute": 100,
                    "approval_ttl_seconds": 900,
                    "quarantine_threshold": 2,
                    "quarantine_window_seconds": 300,
                    "max_egress_bytes": 100,
                    "hourly_egress_bytes": 1000,
                },
                "tools": {
                    "search_knowledge": {
                        "risk": "low",
                        "effect": "allow",
                        "allowed_agents": ["research-agent"],
                        "required_scopes": ["tools:search"],
                        "sensitive": False,
                        "egress": False,
                        "category": "knowledge_read",
                    },
                    "send_email": {
                        "risk": "high",
                        "effect": "require_approval",
                        "allowed_agents": ["research-agent"],
                        "required_scopes": ["tools:email:send"],
                        "sensitive": True,
                        "requires_provenance": True,
                        "egress": True,
                        "dlp_action": "deny",
                        "category": "egress",
                        "max_input_classification": "internal",
                        "classification_violation_action": "deny",
                        "blocked_taint_labels": [
                            "prompt_injection",
                            "customer-data",
                            "restricted",
                        ],
                    },
                    "delete_record": {
                        "risk": "critical",
                        "effect": "deny",
                        "allowed_agents": [],
                        "required_scopes": ["tools:record:delete"],
                        "sensitive": True,
                        "egress": False,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def signer() -> TokenSigner:
    return TokenSigner("test-token-signing-key-at-least-24", "test-issuer")


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(
        tmp_path / "test.db", "test-audit-key", "test-data-encryption-key-at-least-24"
    )


@pytest.fixture
def service(policy_file: Path, signer: TokenSigner, store: Store) -> GatewayService:
    return GatewayService(
        PolicyEngine(policy_file),
        store,
        ProvenanceService(signer),
        demo_registry(),
    )


@pytest.fixture
def principal() -> AgentPrincipal:
    return AgentPrincipal(
        agent_id="research-agent",
        tenant_id="tenant-1",
        scopes=frozenset({"tools:search", "tools:email:send", "provenance:attest"}),
        token_id="token-1",
        expires_at=utc_now() + timedelta(hours=1),
    )


@pytest.fixture
def mixed_token(service: GatewayService, principal: AgentPrincipal) -> str:
    return service.provenance.attest(
        ProvenanceAttestRequest(
            source_id="user-request",
            content="Please perform the requested action.",
            trust=TrustLevel.MIXED,
        ),
        principal.tenant_id,
    ).token
