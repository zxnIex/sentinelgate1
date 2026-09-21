"""Fail-closed stateless HTTP MCP upstream mediation."""

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from sentinelgate.executor import ToolExecutionError, ToolResult
from sentinelgate.mcp import _error, _result, handle_mcp
from sentinelgate.mcp_security import inspect_manifest
from sentinelgate.models import (
    AgentPrincipal,
    DataClassification,
    MCPManifestInspectionRequest,
    MCPToolDefinition,
    TrustLevel,
)
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store


class UpstreamMCPError(RuntimeError):
    pass


class UpstreamMCPManager:
    def __init__(
        self,
        config_path: Path,
        store: Store,
        client: httpx.Client | None = None,
    ):
        self.config_path = config_path
        self.store = store
        self.client = client or httpx.Client(
            timeout=10.0, follow_redirects=False, trust_env=False
        )

    def server_ids(self) -> list[str]:
        return sorted(self._load_servers())

    def sync_and_register(
        self,
        server_id: str,
        principal: AgentPrincipal,
        service: GatewayService,
    ) -> dict[str, str]:
        config = self._server_config(server_id)
        self._authorize(config, principal)
        tools = self._discover(server_id, config)
        report = inspect_manifest(
            server_id,
            MCPManifestInspectionRequest(tools=tools),
            self.store,
        )
        if not report.safe or not report.accepted or any(
            item.status != "trusted" for item in report.tools
        ):
            raise UpstreamMCPError("MCP manifest failed integrity enforcement")

        names: dict[str, str] = {}
        for tool in tools:
            runtime_name = f"mcp.{server_id}.{tool.name}"
            names[tool.name] = runtime_name
            tool_overrides = config.get("tool_overrides", {}).get(tool.name, {})
            if not isinstance(tool_overrides, dict):
                raise UpstreamMCPError("Invalid MCP tool override")
            sensitive = bool(tool_overrides.get("sensitive", False))
            egress = bool(tool_overrides.get("egress", False))
            guarded = sensitive or egress
            policy = {
                "risk": str(tool_overrides.get("risk", config.get("risk", "medium"))),
                "effect": str(
                    tool_overrides.get(
                        "effect", "require_approval" if guarded else "allow"
                    )
                ),
                "allowed_agents": list(config.get("allowed_agents", [])),
                "required_scopes": list(config.get("required_scopes", [])),
                "sensitive": sensitive,
                "requires_provenance": bool(
                    tool_overrides.get("requires_provenance", guarded)
                ),
                "egress": egress,
                "category": str(tool_overrides.get("category", "mcp_upstream")),
                "mcp_server_id": server_id,
                "mcp_tool_name": tool.name,
            }
            if egress:
                policy.update(
                    {
                        "blocked_taint_labels": list(
                            tool_overrides.get(
                                "blocked_taint_labels",
                                [
                                    "customer-data",
                                    "prompt-injection",
                                    "restricted",
                                    "secret",
                                ],
                            )
                        ),
                        "max_input_classification": str(
                            tool_overrides.get(
                                "max_input_classification", "internal"
                            )
                        ),
                        "classification_violation_action": str(
                            tool_overrides.get(
                                "classification_violation_action", "deny"
                            )
                        ),
                        "dlp_action": str(
                            tool_overrides.get("dlp_action", "deny")
                        ),
                    }
                )
            for key in (
                "max_string_length",
                "max_egress_bytes",
                "hourly_egress_bytes",
                "blocked_argument_patterns",
            ):
                if key in tool_overrides:
                    policy[key] = tool_overrides[key]
            service.policy.register_runtime_tool(runtime_name, policy)
            service.executor.register_schema(
                runtime_name,
                self._handler(server_id, tool.name, config),
                tool.inputSchema,
                tool.description,
            )
        return names

    def _handler(self, server_id: str, tool_name: str, config: dict[str, Any]):
        def invoke(arguments: dict[str, Any]) -> ToolResult:
            response = self._post(config, {
                "jsonrpc": "2.0", "id": "sentinelgate-call", "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            })
            if "error" in response:
                raise ToolExecutionError("Upstream MCP tool returned an error")
            result = response.get("result")
            if not isinstance(result, dict) or result.get("isError") is True:
                raise ToolExecutionError("Upstream MCP tool failed")
            output = result.get("structuredContent", result.get("content"))
            return ToolResult(
                output=output,
                trust=TrustLevel(str(config.get("output_trust", "untrusted"))),
                classification=DataClassification(
                    str(config.get("output_classification", "internal"))
                ),
                labels=frozenset({
                    "mcp_upstream", f"mcp_server:{server_id}",
                    *[str(item) for item in config.get("output_labels", [])],
                }),
                sources=(f"mcp:{server_id}:{tool_name}",),
            )
        return invoke

    def _discover(
        self, server_id: str, config: dict[str, Any]
    ) -> list[MCPToolDefinition]:
        raw_tools: list[object] = []
        cursor: str | None = None
        for page in range(20):
            request_id = f"sentinelgate-list-{page}"
            payload: dict[str, Any] = {
                "jsonrpc": "2.0", "id": request_id, "method": "tools/list",
            }
            if cursor is not None:
                payload["params"] = {"cursor": cursor}
            response = self._post(config, payload)
            result = response.get("result")
            page_tools = result.get("tools") if isinstance(result, dict) else None
            if not isinstance(page_tools, list):
                raise UpstreamMCPError(
                    f"MCP server {server_id} returned an invalid tools page"
                )
            raw_tools.extend(page_tools)
            if len(raw_tools) > 500:
                raise UpstreamMCPError("MCP server exposes more than 500 tools")
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                break
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                raise UpstreamMCPError("MCP server returned an invalid pagination cursor")
            cursor = next_cursor
        else:
            raise UpstreamMCPError("MCP tools/list exceeded 20 pages")
        if not raw_tools:
            raise UpstreamMCPError(f"MCP server {server_id} returned no valid tools")
        try:
            return [MCPToolDefinition.model_validate(item) for item in raw_tools]
        except (TypeError, ValueError) as exc:
            raise UpstreamMCPError("MCP server returned an invalid manifest") from exc

    def _post(self, config: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        url = str(config["url"])
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "MCP-Protocol-Version": str(config.get("protocol_version", "2025-06-18")),
        }
        token_env = config.get("bearer_token_env")
        if token_env:
            token = os.environ.get(str(token_env))
            if not token:
                raise UpstreamMCPError("Configured MCP bearer-token environment variable is missing")
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = self.client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            maximum = int(config.get("max_response_bytes", 2_000_000))
            if len(response.content) > maximum:
                raise UpstreamMCPError("MCP upstream response exceeds configured limit")
            content_type = response.headers.get("content-type", "").casefold()
            if "application/json" not in content_type:
                raise UpstreamMCPError("MCP upstream did not return JSON")
            body = response.json()
        except UpstreamMCPError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise UpstreamMCPError("MCP upstream request failed") from exc
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            raise UpstreamMCPError("MCP upstream returned invalid JSON-RPC")
        if body.get("id") != payload.get("id"):
            raise UpstreamMCPError("MCP upstream response id mismatch")
        return body

    def _server_config(self, server_id: str) -> dict[str, Any]:
        config = self._load_servers().get(server_id)
        if not isinstance(config, dict):
            raise UpstreamMCPError("Unknown MCP upstream")
        url = str(config.get("url", ""))
        parsed = urlparse(url)
        local = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
        if parsed.scheme != "https" and not local:
            raise UpstreamMCPError("MCP upstream must use HTTPS or local development HTTP")
        if parsed.username or parsed.password or parsed.fragment:
            raise UpstreamMCPError("MCP upstream URL is invalid")
        return config

    def _load_servers(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UpstreamMCPError("Cannot load MCP upstream configuration") from exc
        servers = payload.get("servers") if isinstance(payload, dict) else None
        if not isinstance(servers, dict):
            raise UpstreamMCPError("MCP configuration requires a servers object")
        return servers

    @staticmethod
    def _authorize(config: dict[str, Any], principal: AgentPrincipal) -> None:
        if principal.agent_id not in config.get("allowed_agents", []):
            raise UpstreamMCPError("Agent is not authorized for MCP upstream")
        missing = set(config.get("required_scopes", [])) - set(principal.scopes)
        if missing:
            raise UpstreamMCPError("Agent is missing MCP upstream scope")


def handle_upstream_mcp(
    server_id: str,
    payload: dict[str, Any],
    principal: AgentPrincipal,
    service: GatewayService,
    manager: UpstreamMCPManager,
) -> dict[str, Any]:
    request_id = payload.get("id")
    method = payload.get("method")
    try:
        names = manager.sync_and_register(server_id, principal, service)
    except UpstreamMCPError as exc:
        return _error(request_id, -32001, str(exc))
    if method == "tools/list":
        definitions = {
            item["name"]: item for item in service.available_tools(principal)
        }
        visible = []
        for original, runtime in names.items():
            definition = dict(definitions[runtime])
            definition["name"] = original
            definition.setdefault("_meta", {})["sentinelgate"] = {
                "upstream": server_id, "runtime_name": runtime,
            }
            visible.append(definition)
        return _result(request_id, {"tools": visible})
    if method == "tools/call":
        params = payload.get("params") or {}
        original = params.get("name") if isinstance(params, dict) else None
        if original not in names:
            return _error(request_id, -32602, "Unknown upstream tool")
        rewritten = dict(payload)
        rewritten["params"] = dict(params) | {"name": names[original]}
        return handle_mcp(
            rewritten, principal, service, forced_mcp_server_id=server_id
        )
    return handle_mcp(payload, principal, service)
