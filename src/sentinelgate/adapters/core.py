from __future__ import annotations

import inspect
import os
from collections.abc import Callable
from typing import Any

from sentinelgate.client import AsyncSentinelGateClient, SentinelGateClient


class GuardedToolError(RuntimeError):
    pass


class GuardedCallable:
    """Execute a local callable only after the gateway allows its exact input."""

    def __init__(
        self,
        function: Callable[..., Any],
        *,
        tool_name: str | None = None,
        client: SentinelGateClient | None = None,
        user_id: str = "framework-user",
    ) -> None:
        self.function = function
        self.tool_name = tool_name or function.__name__
        self.client = client
        self.user_id = user_id

    def __call__(self, **arguments: Any) -> Any:
        client = self.client or SentinelGateClient.from_env()
        owns_client = self.client is None
        try:
            result = client.evaluate(
                user_id=self.user_id,
                tool_name=self.tool_name,
                arguments=arguments,
            )
            decision = result.get("decision")
            if decision != "allow":
                raise GuardedToolError(
                    f"Tool {self.tool_name} was {decision}: "
                    f"{', '.join(result.get('reason_codes', []))}"
                )
            value = self.function(**arguments)
            if inspect.isawaitable(value):
                raise GuardedToolError(
                    "Async tool supplied to sync adapter; use AsyncGuardedCallable"
                )
            return value
        finally:
            if owns_client:
                client.close()


class AsyncGuardedCallable:
    """Async equivalent that does not block an agent runtime's event loop."""

    def __init__(
        self,
        function: Callable[..., Any],
        *,
        tool_name: str | None = None,
        client: AsyncSentinelGateClient | None = None,
        user_id: str = "framework-user",
    ) -> None:
        self.function = function
        self.tool_name = tool_name or function.__name__
        self.client = client
        self.user_id = user_id

    async def __call__(self, **arguments: Any) -> Any:
        client = self.client or AsyncSentinelGateClient.from_env()
        owns_client = self.client is None
        try:
            result = await client.evaluate(
                user_id=self.user_id,
                tool_name=self.tool_name,
                arguments=arguments,
            )
            decision = result.get("decision")
            if decision != "allow":
                raise GuardedToolError(
                    f"Tool {self.tool_name} was {decision}: "
                    f"{', '.join(result.get('reason_codes', []))}"
                )
            value = self.function(**arguments)
            return await value if inspect.isawaitable(value) else value
        finally:
            if owns_client:
                await client.close()


def environment_ready() -> bool:
    return bool(os.getenv("SENTINEL_AGENT_TOKEN") and os.getenv("SENTINEL_BASE_URL"))
