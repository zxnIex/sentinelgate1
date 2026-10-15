"""Complete OpenAI Responses example with every tool call routed through the gate."""

from __future__ import annotations

import hashlib
import json
import os
from uuid import uuid4

from dotenv import load_dotenv
from openai import OpenAI

from sentinelgate.client import SentinelGateClient

TOOLS = [
    {
        "type": "function",
        "name": "search_knowledge",
        "description": "Search governed company documentation.",
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
        "description": "Send an external email; approval may be required.",
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


def main() -> None:
    load_dotenv(override=False)
    prompt = input("Ask the protected agent: ").strip()
    if not prompt:
        raise SystemExit("Enter a task")
    trace_id = str(uuid4())
    openai = OpenAI()
    with SentinelGateClient.from_env() as gate:
        source = gate.attest_structured(
            "user-input",
            {"prompt": prompt},
            trust="mixed",
            trace_id=trace_id,
        )
        provenance = [source["token"]]
        history: list[object] = [{"role": "user", "content": prompt}]
        for _ in range(8):
            response = openai.responses.create(
                model=os.getenv("OPENAI_MODEL", "gpt-5.6-terra"),
                instructions=(
                    "Use tools when useful. A pending approval is not success. "
                    "Never bypass the security gateway or claim a rejected call ran."
                ),
                input=history,
                tools=TOOLS,
                parallel_tool_calls=False,
                store=False,
                safety_identifier=hashlib.sha256(b"protected-agent-demo").hexdigest()[
                    :32
                ],
            )
            history.extend(response.output)
            calls = [item for item in response.output if item.type == "function_call"]
            if not calls:
                print(response.output_text)
                return
            for call in calls:
                result = gate.execute(
                    user_id="example-user",
                    tool_name=call.name,
                    arguments=json.loads(call.arguments),
                    provenance_tokens=provenance,
                    purpose="complete protected-agent example",
                    trace_id=trace_id,
                )
                if result.get("output_provenance_token"):
                    provenance.append(result["output_provenance_token"])
                visible = {
                    key: value
                    for key, value in result.items()
                    if key != "output_provenance_token"
                }
                history.append(
                    {
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": json.dumps(visible),
                    }
                )
    raise SystemExit("Agent exceeded eight tool rounds")


if __name__ == "__main__":
    main()
