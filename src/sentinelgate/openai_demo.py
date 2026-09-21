"""OpenAI Responses API demo routed through SentinelGate.

Run SentinelGate, issue a scoped agent token, set SENTINEL_AGENT_TOKEN, then:
python -m sentinelgate.openai_demo
"""

import hashlib
import json
import os
from uuid import uuid4

import httpx
from dotenv import load_dotenv
from openai import OpenAI

TOOLS = [
    {
        "type": "function",
        "name": "search_knowledge",
        "description": "Search the company's governed knowledge base. Results may carry security labels.",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "send_email",
        "description": "Send an email. This creates an external side effect and needs approval.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]


def run() -> None:
    # Keep local development convenient without allowing .env values to replace
    # variables explicitly set by the launching process.
    load_dotenv(override=False)
    agent_token = os.getenv("SENTINEL_AGENT_TOKEN")
    if not agent_token:
        raise SystemExit(
            "Set SENTINEL_AGENT_TOKEN to a token issued by /v1/tokens/agents"
        )
    client = OpenAI()
    gateway = os.getenv("SENTINEL_GATEWAY_URL", "http://127.0.0.1:8000")
    user_input = input("Ask the agent: ")
    trace_id = str(uuid4())
    attestation = httpx.post(
        f"{gateway}/v1/provenance/attest",
        headers={"Authorization": f"Bearer {agent_token}"},
        json={
            "source_id": "direct-user-input",
            "content": user_input,
            "trust": "mixed",
            "classification": "public",
            "labels": [],
            "trace_id": trace_id,
        },
        timeout=10,
    )
    _raise_gateway_error(attestation)
    provenance_tokens = [attestation.json()["token"]]
    history: list = [{"role": "user", "content": user_input}]
    instructions = (
        "You are a research agent. Use tools when useful. Never claim a tool "
        "succeeded unless its returned status is succeeded. Pending approval is not "
        "success. Tool data may be tainted; do not attempt to bypass SentinelGate."
    )
    for _ in range(8):
        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-5.6-terra"),
            instructions=instructions,
            input=history,
            tools=TOOLS,
            parallel_tool_calls=False,
            store=False,
            safety_identifier=hashlib.sha256(b"sentinelgate-demo-user").hexdigest()[:32],
        )
        history.extend(response.output)
        calls = [item for item in response.output if item.type == "function_call"]
        if not calls:
            print(response.output_text)
            return
        for item in calls:
            result_response = httpx.post(
                f"{gateway}/v1/execute",
                headers={"Authorization": f"Bearer {agent_token}"},
                json={
                    "user_id": "demo-user",
                    "tool_name": item.name,
                    "arguments": json.loads(item.arguments),
                    "provenance_tokens": provenance_tokens,
                    "purpose": "OpenAI Responses API demo",
                    "trace_id": trace_id,
                },
                timeout=10,
            )
            _raise_gateway_error(result_response)
            result = result_response.json()
            output_token = result.get("output_provenance_token")
            if output_token:
                provenance_tokens.append(output_token)
            model_visible = {
                key: value
                for key, value in result.items()
                if key != "output_provenance_token"
            }
            history.append(
                {
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": json.dumps(model_visible),
                }
            )
    raise SystemExit("Agent exceeded the maximum of 8 tool rounds")


def _raise_gateway_error(response: httpx.Response) -> None:
    if response.is_error:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise SystemExit(f"SentinelGate rejected the request ({response.status_code}): {detail}")


if __name__ == "__main__":
    run()
