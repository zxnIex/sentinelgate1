import argparse
import asyncio
import json
from pathlib import Path

import pytest

from sentinelgate.adapters.core import (
    AsyncGuardedCallable,
    GuardedCallable,
    GuardedToolError,
)
from sentinelgate.adapters.mcp import MCPGatewayConfig
from sentinelgate.cli import initialize
from sentinelgate.dashboard import branded_page
from sentinelgate.funnel import FunnelRecorder
from sentinelgate.onboarding import (
    OnboardingError,
    discover_tools,
    generate_starter_policy,
    integration_snippet,
)


class FakeClient:
    def __init__(self, decision: str) -> None:
        self.decision = decision

    def evaluate(self, **_kwargs):
        return {"decision": self.decision, "reason_codes": ["TEST"]}


class FakeAsyncClient:
    def __init__(self, decision: str) -> None:
        self.decision = decision

    async def evaluate(self, **_kwargs):
        return {"decision": self.decision, "reason_codes": ["TEST"]}


def test_discovery_and_policy_are_conservative():
    tools = discover_tools(
        [
            {
                "type": "function",
                "function": {
                    "name": "list_records",
                    "parameters": {"type": "object"},
                },
            },
            {"name": "delete_record", "inputSchema": {"type": "object"}},
        ]
    )
    draft = generate_starter_policy(tools, "agent-1")
    assert draft["review_required"] is True
    assert draft["policy"]["tools"]["list_records"]["effect"] == "require_approval"
    assert draft["policy"]["tools"]["delete_record"]["effect"] == "deny"


def test_discovery_rejects_invalid_and_duplicate_tools():
    with pytest.raises(OnboardingError, match="Duplicate"):
        discover_tools([{"name": "same"}, {"name": "same"}])
    with pytest.raises(OnboardingError, match="Invalid tool name"):
        discover_tools([{"name": "bad name"}])


def test_framework_snippets_and_mcp_configuration():
    assert "guarded_function_tool" in integration_snippet("openai-agents")
    assert "guard_langchain_tool" in integration_snippet("langgraph")
    config = MCPGatewayConfig("https://gate.example/", "secret", "docs")
    assert config.url == "https://gate.example/mcp/upstream/docs"
    assert config.headers == {"Authorization": "Bearer secret"}


def test_guarded_callable_never_invokes_a_denied_tool():
    invoked = []

    def danger(value: str) -> str:
        invoked.append(value)
        return value

    guarded = GuardedCallable(danger, client=FakeClient("deny"))
    with pytest.raises(GuardedToolError, match="was deny"):
        guarded(value="no")
    assert invoked == []


def test_async_guarded_callable_preserves_async_execution():
    async def tool(value: str) -> str:
        return value.upper()

    guarded = AsyncGuardedCallable(tool, client=FakeAsyncClient("allow"))
    assert asyncio.run(guarded(value="safe")) == "SAFE"


def test_init_preserves_existing_configuration_when_rotating(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        "SENTINEL_ADMIN_TOKEN=old\nSENTINEL_GITHUB_APP_ID=123\n# keep me\n",
        encoding="utf-8",
    )
    args = argparse.Namespace(
        directory=str(tmp_path),
        telemetry=False,
        rotate_secrets=True,
        force_policy=False,
        product_name="Test Control Plane",
    )
    assert initialize(args) == 0
    updated = env.read_text(encoding="utf-8")
    assert "SENTINEL_GITHUB_APP_ID=123" in updated
    assert "# keep me" in updated
    assert "SENTINEL_ADMIN_TOKEN=old" not in updated
    assert "POSTGRES_PASSWORD=" in updated


def test_funnel_is_opt_in_and_allowlisted(tmp_path: Path):
    FunnelRecorder(tmp_path).record("init_started")
    assert not (tmp_path / ".sentinelgate").exists()
    recorder = FunnelRecorder(tmp_path, enabled=True)
    recorder.record("not-allowed")
    assert not (tmp_path / ".sentinelgate").exists()
    recorder.record("init_started")
    payload = json.loads(
        (tmp_path / ".sentinelgate" / "onboarding-events.jsonl").read_text()
    )
    assert set(payload) == {
        "schema_version",
        "installation_id",
        "event",
        "success",
        "occurred_at",
        "product_version",
    }


def test_display_brand_is_escaped_and_does_not_change_api_name():
    rendered = branded_page("<h1>SentinelGate v0.17.0</h1>", "A&B <Control>")
    assert rendered == "<h1>A&amp;B &lt;Control&gt; v0.17.0</h1>"
