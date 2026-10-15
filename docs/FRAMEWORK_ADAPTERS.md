# Framework adapters

SentinelGate's stable boundary is the HTTP API. Adapters reduce integration work but cannot protect
tools that remain callable through an unmediated path.

## OpenAI Agents SDK

```python
from agents import Agent
from sentinelgate.adapters.openai_agents import guarded_function_tool

def search_knowledge(query: str) -> str:
    """Search governed documentation."""
    return query

agent = Agent(name="Research", tools=[guarded_function_tool(search_knowledge)])
```

The adapter retains the source function's signature and documentation so the SDK can derive its
schema. It evaluates the exact arguments before calling the local function.

## LangGraph

```python
from langchain_core.tools import tool
from sentinelgate.adapters.langgraph import guard_langchain_tool

@tool
def search_knowledge(query: str) -> str:
    """Search governed documentation."""
    return query

secured = guard_langchain_tool(search_knowledge)
```

Place `secured`, not the original object, in the graph's tool node and do not expose the original
dispatcher elsewhere.

## MCP

```python
from sentinelgate.adapters.mcp import MCPGatewayConfig

config = MCPGatewayConfig(
    "http://127.0.0.1:8000",
    agent_token,
    upstream_server_id="docs",
)
print(config.as_client_config())
```

The gateway refreshes and inspects upstream definitions before calls. The current MCP transport
limitations in `SECURITY.md` still apply.

## Security boundary

The local adapters are pre-execution gates. They can stop a denied input before application code
runs. They do not make arbitrary local function output cryptographically attributable and cannot
roll back side effects. For end-to-end output provenance, DLP, execution claims, and one-time
approval semantics, register a governed connector and call `/v1/execute`.
