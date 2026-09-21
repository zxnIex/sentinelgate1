import json

import httpx
import pytest

from sentinelgate.client import SentinelGateClient, SentinelGateError


def test_client_builds_attestation_and_execution_requests():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.headers, json.loads(request.content)))
        if request.url.path.endswith("attest"):
            return httpx.Response(200, json={"token": "provenance-token"})
        return httpx.Response(200, json={"status": "succeeded"})

    with SentinelGateClient(
        "https://gateway.example",
        "agent-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        assert client.attest("page", "external content")["token"] == "provenance-token"
        result = client.execute(
            user_id="u",
            tool_name="search_knowledge",
            arguments={"query": "security"},
            trace_id="trace-1",
        )
    assert result["status"] == "succeeded"
    assert seen[0][1]["authorization"] == "Bearer agent-token"
    assert seen[1][2]["trace_id"] == "trace-1"


def test_client_fails_closed_on_gateway_error():
    transport = httpx.MockTransport(lambda _: httpx.Response(503))
    with (
        SentinelGateClient(
            "https://gateway.example", "token", transport=transport
        ) as client,
        pytest.raises(SentinelGateError),
    ):
        client.evaluate(user_id="u", tool_name="search_knowledge", arguments={})
