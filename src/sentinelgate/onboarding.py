"""Framework-neutral onboarding, policy generation and integration snippets."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator, SchemaError


class OnboardingError(ValueError):
    pass


@dataclass(frozen=True)
class DiscoveredTool:
    name: str
    description: str
    input_schema: dict[str, Any]


DESTRUCTIVE_WORDS = frozenset(
    {"delete", "destroy", "drop", "terminate", "revoke", "purge", "erase", "shell"}
)
WRITE_WORDS = frozenset(
    {"send", "create", "update", "write", "post", "publish", "commit", "merge"}
)


def discover_tools(payload: Any) -> list[DiscoveredTool]:
    """Normalize OpenAI or MCP tool definitions without executing or importing them."""
    if isinstance(payload, dict) and "tools" in payload:
        payload = payload["tools"]
    if not isinstance(payload, list) or not payload:
        raise OnboardingError("Tool input must be a non-empty list or an object with tools")
    if len(payload) > 500:
        raise OnboardingError("At most 500 tools may be imported")
    discovered: list[DiscoveredTool] = []
    names: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise OnboardingError("Every tool definition must be an object")
        function = raw.get("function") if raw.get("type") == "function" else raw
        if not isinstance(function, dict):
            raise OnboardingError("OpenAI function definition is malformed")
        name = str(function.get("name", "")).strip()
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", name):
            raise OnboardingError(f"Invalid tool name: {name or '<missing>'}")
        if name in names:
            raise OnboardingError(f"Duplicate tool name: {name}")
        schema = function.get("parameters", function.get("inputSchema", {}))
        if not isinstance(schema, dict):
            raise OnboardingError(f"Tool schema must be an object: {name}")
        schema = dict(schema) or {"type": "object", "additionalProperties": False}
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise OnboardingError(f"Invalid JSON Schema for {name}") from exc
        discovered.append(
            DiscoveredTool(
                name=name,
                description=str(function.get("description", ""))[:2_000],
                input_schema=schema,
            )
        )
        names.add(name)
    return discovered


def generate_starter_policy(
    tools: list[DiscoveredTool], agent_id: str
) -> dict[str, Any]:
    """Generate a conservative draft. Name heuristics never silently grant write access."""
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", agent_id):
        raise OnboardingError("Invalid agent ID")
    policy_tools: dict[str, dict[str, Any]] = {}
    reviews: list[dict[str, str]] = []
    for tool in tools:
        words = {word for word in re.split(r"[^a-z0-9]+", tool.name.casefold()) if word}
        destructive = bool(words & DESTRUCTIVE_WORDS)
        write = bool(words & WRITE_WORDS)
        if destructive:
            effect, risk = "deny", "critical"
            category = "destructive"
        elif write:
            effect, risk = "require_approval", "high"
            category = "external_write"
        else:
            effect, risk = "require_approval", "medium"
            category = "unclassified"
        policy_tools[tool.name] = {
            "risk": risk,
            "effect": effect,
            "allowed_agents": [agent_id],
            "required_scopes": [f"tools:{tool.name}"],
            "sensitive": destructive or write,
            "requires_provenance": destructive or write,
            "egress": write,
            "category": category,
            "input_schema": tool.input_schema,
        }
        reviews.append(
            {
                "tool": tool.name,
                "suggested_effect": effect,
                "reason": (
                    "destructive name signal"
                    if destructive
                    else "write name signal"
                    if write
                    else "unknown semantics; approval is the safe default"
                ),
            }
        )
    return {
        "policy": {
            "version": "generated-draft-1",
            "defaults": {
                "unknown_tool": "deny",
                "requests_per_minute": 60,
                "approval_ttl_seconds": 900,
                "max_string_length": 10_000,
                "max_egress_bytes": 100_000,
                "hourly_egress_bytes": 1_000_000,
            },
            "tools": policy_tools,
        },
        "review_required": True,
        "review_items": reviews,
        "warning": (
            "Generated policy is a conservative draft based partly on tool names. "
            "Review tool semantics, data classification, scopes and egress before enforcement."
        ),
    }


FRAMEWORKS = ("python", "openai-agents", "langgraph", "mcp")


def integration_snippet(framework: str, *, tool_name: str = "search_knowledge") -> str:
    if framework not in FRAMEWORKS:
        raise OnboardingError(f"Unsupported framework: {framework}")
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", tool_name):
        raise OnboardingError("Invalid tool name")
    if framework == "python":
        return f'''from sentinelgate.client import SentinelGateClient

with SentinelGateClient.from_env() as gate:
    result = gate.execute(
        user_id="user-123",
        tool_name="{tool_name}",
        arguments={{"query": "security policy"}},
    )
    print(result)
'''
    if framework == "openai-agents":
        return f'''from agents import Agent, Runner
from sentinelgate.adapters.openai_agents import guarded_function_tool

def {tool_name}(query: str) -> str:
    return f"Demo result for {{query}}"

secured_tool = guarded_function_tool({tool_name})
agent = Agent(name="Protected agent", tools=[secured_tool])
result = Runner.run_sync(agent, "Search for the security policy")
print(result.final_output)
'''
    if framework == "langgraph":
        return f'''from langchain_core.tools import tool
from sentinelgate.adapters.langgraph import guard_langchain_tool

@tool
def {tool_name}(query: str) -> str:
    """Search the governed knowledge base."""
    return f"Demo result for {{query}}"

secured_tool = guard_langchain_tool({tool_name})
# Put secured_tool in your ToolNode instead of the original tool.
'''
    return '''# Configure your MCP client to use the gateway, not the upstream directly.
MCP URL: http://127.0.0.1:8000/mcp
Authorization: Bearer $SENTINEL_AGENT_TOKEN

# For a configured upstream:
MCP URL: http://127.0.0.1:8000/mcp/upstream/<server-id>
'''


def load_tool_file(raw: str) -> list[DiscoveredTool]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OnboardingError("Tool file is not valid JSON") from exc
    return discover_tools(payload)
