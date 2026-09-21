from typing import Any

from sentinelgate.models import AgentPrincipal, ToolCallRequest
from sentinelgate.security import canonical_json
from sentinelgate.service import GatewayService

PROTOCOL_VERSION = "2025-06-18"


def handle_mcp(
    payload: dict[str, Any],
    principal: AgentPrincipal,
    service: GatewayService,
    forced_mcp_server_id: str | None = None,
) -> dict[str, Any]:
    """Handle the stateless JSON-RPC subset needed for MCP tool discovery/calls."""
    request_id = payload.get("id")
    if payload.get("jsonrpc") != "2.0" or not isinstance(payload.get("method"), str):
        return _error(request_id, -32600, "Invalid JSON-RPC request")
    method = payload["method"]
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        return _error(request_id, -32602, "params must be an object")

    if method == "initialize":
        return _result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "SentinelGate", "version": "0.7.0"},
                "instructions": (
                    "All tool calls are identity-, provenance-, taint- and policy-checked. "
                    "Pass trace metadata in params._meta.sentinelgate."
                ),
            },
        )
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": service.available_tools(principal)})
    if method != "tools/call":
        return _error(request_id, -32601, "Method not found")

    name = params.get("name")
    arguments = params.get("arguments") or {}
    metadata = (params.get("_meta") or {}).get("sentinelgate") or {}
    if not isinstance(name, str) or not isinstance(arguments, dict) or not isinstance(metadata, dict):
        return _error(request_id, -32602, "Invalid tool call parameters")
    try:
        call = ToolCallRequest(
            user_id=str(metadata.get("user_id", "mcp-user")),
            tool_name=name,
            arguments=arguments,
            provenance_tokens=metadata.get("provenance_tokens") or [],
            purpose=str(metadata.get("purpose", "MCP tool invocation")),
            mcp_server_id=forced_mcp_server_id,
            **({"trace_id": metadata["trace_id"]} if metadata.get("trace_id") else {}),
        )
    except (TypeError, ValueError):
        return _error(request_id, -32602, "Invalid SentinelGate metadata")

    execution = service.execute(call, principal)
    visible = {
        "status": execution.status,
        "output": execution.output,
        "decision": execution.decision.decision.value if execution.decision else None,
        "reasons": execution.decision.reason_codes if execution.decision else [],
        "approval_id": execution.approval_id,
        "classification": execution.classification.value if execution.classification else None,
        "taint_labels": execution.taint_labels,
        "trace_id": execution.trace_id or call.trace_id,
    }
    security_metadata = {
        "trace_id": execution.trace_id or call.trace_id,
        "output_provenance_token": execution.output_provenance_token,
        "enforcement_mode": (
            execution.decision.enforcement_mode.value if execution.decision else None
        ),
    }
    return _result(
        request_id,
        {
            "content": [{"type": "text", "text": canonical_json(visible)}],
            "structuredContent": visible,
            "isError": execution.status != "succeeded",
            "_meta": {"sentinelgate": security_metadata},
        },
    )


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
