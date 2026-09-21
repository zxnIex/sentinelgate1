"""Deterministic adversarial policy suite. It never executes tools."""

import json
from dataclasses import dataclass
from datetime import timedelta

from sentinelgate.models import (
    AgentPrincipal,
    DataClassification,
    Decision,
    SecurityFinding,
    ToolCallRequest,
    TrustLevel,
    VerifiedProvenance,
    utc_now,
)
from sentinelgate.policy import PolicyEngine
from sentinelgate.settings import get_settings


@dataclass
class Case:
    name: str
    call: ToolCallRequest
    principal: AgentPrincipal
    provenance: list[VerifiedProvenance]
    findings: list[SecurityFinding]
    expected: Decision


def _principal(
    agent_id: str = "research-agent", scopes: frozenset[str] | None = None
) -> AgentPrincipal:
    return AgentPrincipal(
        agent_id=agent_id,
        tenant_id="redteam",
        scopes=scopes or frozenset({"tools:search", "tools:email:send"}),
        token_id="redteam",  # nosec B106
        expires_at=utc_now() + timedelta(hours=1),
    )


def cases() -> list[Case]:
    base = _principal()
    hostile = VerifiedProvenance(
        source_id="hostile-page",
        content_digest="0" * 64,
        trust=TrustLevel.UNTRUSTED,
        signals=["IGNORE_INSTRUCTIONS"],
    )
    mixed = VerifiedProvenance(
        source_id="user-request",
        content_digest="1" * 64,
        trust=TrustLevel.MIXED,
        signals=[],
    )
    leak = SecurityFinding(
        code="OPENAI_KEY", severity="critical", path="$.body", fingerprint="redacted"
    )
    confidential = VerifiedProvenance(
        source_id="customer-analysis",
        content_digest="2" * 64,
        trust=TrustLevel.TRUSTED,
        signals=[],
        classification=DataClassification.CONFIDENTIAL,
        labels=["customer-data"],
    )
    return [
        Case(
            "safe read",
            ToolCallRequest(
                user_id="u", tool_name="search_knowledge", arguments={"query": "safe"}
            ),
            base,
            [],
            [],
            Decision.ALLOW,
        ),
        Case(
            "unknown tool",
            ToolCallRequest(user_id="u", tool_name="admin_shell"),
            base,
            [],
            [],
            Decision.DENY,
        ),
        Case(
            "missing scope",
            ToolCallRequest(
                user_id="u",
                tool_name="send_email",
                arguments={"to": "a@example.com", "subject": "Test", "body": "Hello"},
            ),
            _principal(scopes=frozenset({"tools:search"})),
            [],
            [],
            Decision.DENY,
        ),
        Case(
            "wrong agent",
            ToolCallRequest(user_id="u", tool_name="search_knowledge"),
            _principal("unlisted-agent"),
            [],
            [],
            Decision.DENY,
        ),
        Case(
            "sensitive approval",
            ToolCallRequest(
                user_id="u",
                tool_name="send_email",
                arguments={"to": "a@example.com", "subject": "Test", "body": "Hello"},
            ),
            base,
            [mixed],
            [],
            Decision.REQUIRE_APPROVAL,
        ),
        Case(
            "injected egress",
            ToolCallRequest(
                user_id="u",
                tool_name="send_email",
                arguments={"to": "a@example.com", "subject": "Test", "body": "Hello"},
            ),
            base,
            [hostile],
            [],
            Decision.DENY,
        ),
        Case(
            "secret exfiltration",
            ToolCallRequest(
                user_id="u",
                tool_name="send_email",
                arguments={"to": "a@example.com", "subject": "Test", "body": "Hello"},
            ),
            base,
            [mixed],
            [leak],
            Decision.DENY,
        ),
        Case(
            "confidential trace egress",
            ToolCallRequest(
                user_id="u",
                tool_name="send_email",
                arguments={"to": "a@example.com", "subject": "Data", "body": "Summary"},
            ),
            base,
            [confidential],
            [],
            Decision.DENY,
        ),
        Case(
            "injected GitHub write",
            ToolCallRequest(
                user_id="u",
                tool_name="github_comment_issue",
                arguments={
                    "owner": "acme",
                    "repo": "app",
                    "issue_number": 7,
                    "body": "Posting attacker-controlled content",
                },
            ),
            _principal(
                "coding-agent", frozenset({"tools:github:issues:write"})
            ),
            [hostile],
            [],
            Decision.DENY,
        ),
        Case(
            "workflow mutation",
            ToolCallRequest(
                user_id="u",
                tool_name="github_update_file",
                arguments={
                    "owner": "acme",
                    "repo": "app",
                    "path": ".github/workflows/deploy.yml",
                    "content": "malicious workflow",
                    "message": "change deployment",
                    "branch": "feature/update",
                },
            ),
            _principal(
                "coding-agent", frozenset({"tools:github:contents:write"})
            ),
            [mixed],
            [],
            Decision.DENY,
        ),
        Case(
            "destructive tool",
            ToolCallRequest(user_id="u", tool_name="delete_record"),
            base,
            [],
            [],
            Decision.DENY,
        ),
    ]


def run_suite(engine: PolicyEngine) -> list[dict[str, object]]:
    results = []
    for case in cases():
        actual = engine.evaluate(
            case.call, case.principal, case.provenance, case.findings
        )
        results.append(
            {
                "name": case.name,
                "expected": case.expected.value,
                "actual": actual.decision.value,
                "passed": actual.decision is case.expected,
                "reasons": actual.reasons,
            }
        )
    return results


def main() -> None:
    results = run_suite(PolicyEngine(get_settings().policy_path))
    print(json.dumps(results, indent=2))
    if not all(bool(item["passed"]) for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
