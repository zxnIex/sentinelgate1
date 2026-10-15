"""OpenAI Agents SDK adapter with an optional dependency boundary."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from sentinelgate.adapters.core import AsyncGuardedCallable, GuardedCallable
from sentinelgate.client import AsyncSentinelGateClient, SentinelGateClient


def guarded_function_tool(
    function: Callable[..., Any],
    *,
    tool_name: str | None = None,
    client: SentinelGateClient | AsyncSentinelGateClient | None = None,
    user_id: str = "openai-agents-user",
) -> Any:
    """Return an Agents SDK FunctionTool that preserves the function's schema/docstring."""
    try:
        from agents import function_tool
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError(
            "Install the OpenAI Agents SDK before using this adapter"
        ) from exc
    if inspect.iscoroutinefunction(function):
        if client is not None and not isinstance(client, AsyncSentinelGateClient):
            raise TypeError("Async tools require AsyncSentinelGateClient")
        guarded_async = AsyncGuardedCallable(
            function, tool_name=tool_name, client=client, user_id=user_id
        )

        async def mediated(**arguments: Any) -> Any:
            return await guarded_async(**arguments)

    else:
        if client is not None and not isinstance(client, SentinelGateClient):
            raise TypeError("Sync tools require SentinelGateClient")
        guarded = GuardedCallable(
            function, tool_name=tool_name, client=client, user_id=user_id
        )

        def mediated(**arguments: Any) -> Any:
            return guarded(**arguments)

    mediated.__name__ = tool_name or function.__name__
    mediated.__doc__ = function.__doc__
    mediated.__annotations__ = dict(getattr(function, "__annotations__", {}))
    mediated.__signature__ = inspect.signature(function)  # type: ignore[attr-defined]
    return function_tool(mediated, name_override=tool_name)
