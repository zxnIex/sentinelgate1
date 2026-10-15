"""LangChain/LangGraph tool adapter with no core dependency on either project."""

from __future__ import annotations

from typing import Any

from sentinelgate.adapters.core import GuardedCallable
from sentinelgate.client import SentinelGateClient


def guard_langchain_tool(
    tool: Any,
    *,
    client: SentinelGateClient | None = None,
    user_id: str = "langgraph-user",
) -> Any:
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - optional integration
        raise RuntimeError("Install langchain-core before using this adapter") from exc

    name = str(tool.name)

    def invoke(**arguments: Any) -> Any:
        def original(**values: Any) -> Any:
            return tool.invoke(values)

        return GuardedCallable(
            original, tool_name=name, client=client, user_id=user_id
        )(**arguments)

    return StructuredTool.from_function(
        func=invoke,
        name=name,
        description=str(tool.description),
        args_schema=getattr(tool, "args_schema", None),
    )
