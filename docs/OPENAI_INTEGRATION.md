# OpenAI Responses API integration

Use custom function tools and keep tool execution in your application. For each function
call, pass the exact name and arguments to SentinelGate. Do not invoke the connector unless
the gateway reports `succeeded`.

```python
from sentinelgate.client import SentinelGateClient

with SentinelGateClient("http://127.0.0.1:8000", agent_token) as gate:
    provenance = gate.attest("user-message", user_input, trust="mixed")
    result = gate.execute(
        user_id="user-42",
        tool_name=function_call.name,
        arguments=function_arguments,
        provenance_tokens=[provenance["token"]],
        trace_id=response.id,
        purpose="Answer the user's request",
    )
```

Return the entire result as the function-call output. Teach the model that
`pending_approval`, `denied`, `output_blocked` and `replay_blocked` are not successful tool
execution. The complete loop is in `src/sentinelgate/openai_demo.py`.

Keep `output_provenance_token` in application state rather than exposing it to the model.
Attach it to later calls in the same trace. SentinelGate also retains the resulting taint
server-side, so omitting the token cannot lower the trace classification.

The demo keeps Responses API storage disabled. It therefore sends the first
response's output items and the corresponding function-call outputs together in
the follow-up request instead of using `previous_response_id`.

Use one stable `trace_id` for a user task. SentinelGate uses it to join related actions and
detect transitions such as sensitive data access followed by external egress.

The demo follows the stateless Responses API function-calling loop: it appends every
response output item and each `function_call_output` to the next request while keeping
`store=False`. It allows at most eight tool rounds and uses one UUID trace for the task.
