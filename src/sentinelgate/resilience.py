"""Deterministic local failure and concurrency checks."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from sentinelgate.models import AgentPrincipal, ToolCallRequest, utc_now
from sentinelgate.storage import Store
from sentinelgate.upstream_mcp import UpstreamMCPError, UpstreamMCPManager


def run() -> dict[str, object]:
    results: list[dict[str, object]] = []
    with TemporaryDirectory(prefix="sentinelgate-resilience-") as directory:
        root = Path(directory)
        store = Store(
            root / "resilience.db", "resilience-audit",
            "resilience-encryption-key-32-bytes",
        )
        digest = "a" * 64
        with ThreadPoolExecutor(max_workers=16) as pool:
            claims = list(
                pool.map(lambda _: store.claim_execution("same-request", digest), range(50))
            )
        results.append(
            {"name": "execution replay race", "passed": sum(claims) == 1,
             "detail": f"successful_claims={sum(claims)}"}
        )

        principal = AgentPrincipal(
            agent_id="agent", tenant_id="tenant", scopes=frozenset({"scope"}),
            token_id="resilience-token",  # nosec B106
            expires_at=utc_now() + timedelta(hours=1),
        )
        call = ToolCallRequest(user_id="u", tool_name="tool", arguments={})
        approval = store.create_approval(call, "b" * 64, principal, 300)
        store.resolve_approval(approval.id, "approved", "reviewer", "approved")
        with ThreadPoolExecutor(max_workers=16) as pool:
            consumed = list(pool.map(lambda _: store.consume_approval(approval.id), range(50)))
        results.append(
            {"name": "approval one-time race", "passed": sum(item is not None for item in consumed) == 1,
             "detail": f"successful_consumers={sum(item is not None for item in consumed)}"}
        )

        config = root / "mcp.json"
        config.write_text(json.dumps({"servers": {"test": {
            "url": "https://mcp.example.test", "allowed_agents": ["agent"],
            "required_scopes": ["scope"]
        }}}), encoding="utf-8")

        def unavailable(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"error": "offline"})

        manager = UpstreamMCPManager(
            config, store,
            httpx.Client(transport=httpx.MockTransport(unavailable), trust_env=False),
        )
        failed_closed = False
        try:
            manager._discover("test", manager._server_config("test"))
        except UpstreamMCPError:
            failed_closed = True
        results.append(
            {"name": "MCP upstream outage fails closed", "passed": failed_closed,
             "detail": "503 rejected before tool registration"}
        )

        def malformed(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not-json", headers={"content-type": "text/plain"})

        manager = UpstreamMCPManager(
            config, store,
            httpx.Client(transport=httpx.MockTransport(malformed), trust_env=False),
        )
        rejected = False
        try:
            manager._discover("test", manager._server_config("test"))
        except UpstreamMCPError:
            rejected = True
        results.append(
            {"name": "malformed MCP response fails closed", "passed": rejected,
             "detail": "non-JSON response rejected"}
        )
    return {
        "scope": "local deterministic concurrency and connector-failure checks",
        "passed": sum(bool(item["passed"]) for item in results),
        "total": len(results),
        "results": results,
    }
