"""Small application SDK for routing agent tool calls through SentinelGate."""

from __future__ import annotations

from typing import Any, Self

import httpx


class SentinelGateError(RuntimeError):
    """Raised when the gateway cannot evaluate a request."""


class SentinelGateClient:
    def __init__(
        self,
        base_url: str,
        agent_token: str,
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=timeout,
            transport=transport,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def attest(
        self, source_id: str, content: str, trust: str = "untrusted"
    ) -> dict[str, Any]:
        return self._post(
            "/v1/provenance/attest",
            {"source_id": source_id, "content": content, "trust": trust},
        )

    def evaluate(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None = None,
        purpose: str = "",
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._tool_call(
            "/v1/evaluate", user_id, tool_name, arguments, provenance_tokens,
            purpose, trace_id, request_id,
        )

    def execute(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None = None,
        purpose: str = "",
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._tool_call(
            "/v1/execute", user_id, tool_name, arguments, provenance_tokens,
            purpose, trace_id, request_id,
        )

    def _tool_call(
        self,
        path: str,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None,
        purpose: str,
        trace_id: str | None,
        request_id: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "user_id": user_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "provenance_tokens": provenance_tokens or [],
            "purpose": purpose,
        }
        if trace_id:
            payload["trace_id"] = trace_id
        if request_id:
            payload["request_id"] = request_id
        return self._post(path, payload)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(path, json=payload)
            response.raise_for_status()
            return dict(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise SentinelGateError(f"SentinelGate request failed: {path}") from exc
