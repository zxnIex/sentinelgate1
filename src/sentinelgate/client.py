"""Small application SDK for routing agent tool calls through SentinelGate."""

from __future__ import annotations

import os
from pathlib import Path
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
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @classmethod
    def from_env(cls, *, timeout: float = 10.0) -> SentinelGateClient:
        token = os.getenv("SENTINEL_AGENT_TOKEN", "").strip()
        if not token:
            raise SentinelGateError("SENTINEL_AGENT_TOKEN is not set")
        return cls(
            os.getenv("SENTINEL_BASE_URL", "http://127.0.0.1:8000"),
            token,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def attest(
        self, source_id: str, content: str, trust: str = "untrusted"
    ) -> dict[str, Any]:
        return self._post(
            "/v1/provenance/attest",
            {"source_id": source_id, "content": content, "trust": trust},
        )

    def attest_structured(
        self,
        source_id: str,
        value: Any,
        *,
        trust: str = "untrusted",
        classification: str = "public",
        labels: list[str] | None = None,
        trace_id: str | None = None,
        field_overrides: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source_id": source_id,
            "value": value,
            "trust": trust,
            "classification": classification,
            "labels": labels or [],
            "field_overrides": field_overrides or {},
        }
        if trace_id:
            payload["trace_id"] = trace_id
        return self._post("/v1/provenance/attest-structured", payload)

    def evaluate(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None = None,
        field_provenance: dict[str, list[dict[str, str]]] | None = None,
        purpose: str = "",
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._tool_call(
            "/v1/evaluate",
            user_id,
            tool_name,
            arguments,
            provenance_tokens,
            field_provenance,
            purpose,
            trace_id,
            request_id,
        )

    def execute(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None = None,
        field_provenance: dict[str, list[dict[str, str]]] | None = None,
        purpose: str = "",
        trace_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._tool_call(
            "/v1/execute",
            user_id,
            tool_name,
            arguments,
            provenance_tokens,
            field_provenance,
            purpose,
            trace_id,
            request_id,
        )

    def _tool_call(
        self,
        path: str,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None,
        field_provenance: dict[str, list[dict[str, str]]] | None,
        purpose: str,
        trace_id: str | None,
        request_id: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "user_id": user_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "provenance_tokens": provenance_tokens or [],
            "field_provenance": field_provenance or {},
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
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                detail = f" ({exc.response.status_code}: {exc.response.text[:300]})"
            raise SentinelGateError(
                f"Gateway request failed: {path}{detail}"
            ) from exc


class AsyncSentinelGateClient:
    """Connection-pooled async client for event-loop based agent runtimes."""

    def __init__(
        self,
        base_url: str,
        agent_token: str,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=timeout,
            transport=transport,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    @classmethod
    def from_env(cls, *, timeout: float = 10.0) -> AsyncSentinelGateClient:
        token = os.getenv("SENTINEL_AGENT_TOKEN", "").strip()
        if not token:
            raise SentinelGateError("SENTINEL_AGENT_TOKEN is not set")
        return cls(
            os.getenv("SENTINEL_BASE_URL", "http://127.0.0.1:8000"),
            token,
            timeout=timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def evaluate(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_tokens: list[str] | None = None,
        purpose: str = "",
        trace_id: str | None = None,
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
        try:
            response = await self._client.post("/v1/evaluate", json=payload)
            response.raise_for_status()
            return dict(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                detail = f" ({exc.response.status_code}: {exc.response.text[:300]})"
            raise SentinelGateError(
                f"Gateway request failed: /v1/evaluate{detail}"
            ) from exc


def load_agent_token(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise SentinelGateError(f"Agent token file is empty: {path}")
    return token
