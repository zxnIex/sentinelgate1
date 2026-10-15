# Watch+ Intelligence and Response

Watch+ extends deterministic Watch evidence; it does not replace Gate and it does not make an LLM
an authorization authority.

## Intelligence input boundary

By default, an analysis contains:

- task identifier, profile, state and declared budgets;
- expected tools and milestone identifiers;
- ordered event IDs, event types, tool names, outcomes, error codes, duration, token counts and
  reported cost;
- existing deterministic finding codes and evidence.

It excludes raw prompts, tool arguments and tool results. Task descriptions are withheld unless
the deployment enables `SENTINEL_WATCH_INTELLIGENCE_ALLOW_DESCRIPTION` and the operator explicitly
requests them for that analysis.

The model returns a strict structured assessment. Every evidence reference must match an event that
was supplied to the model. Fabricated references reject the complete assessment. Confidence is
capped at 0.95 because model output is not deterministic proof.

## Response boundary

LLM findings always create a `review_task` proposal with
`automatic_execution_allowed=false`. They cannot pause a task, approve a plan, revoke a token or
change Gate policy.

Automatic response is separately available only when all of these conditions hold:

1. The deployment enables non-monitor Watch and automatic response.
2. The tenant has Watch+ or Enterprise entitlements.
3. An administrator enables a named response policy for a deterministic finding code.
4. The deterministic finding meets the configured confidence threshold.
5. The action is exactly `pause_task`.

Agent-wide quarantine, tool restriction, credential revocation and recovery remain authenticated
human operations. Session revocation affects only tokens cryptographically observed on that Watch
task/session binding; it does not revoke every credential for the agent.

## Configuration

```dotenv
SENTINEL_WATCH_INTELLIGENCE_ENABLED=true
SENTINEL_OPENAI_API_KEY=...
SENTINEL_WATCH_INTELLIGENCE_MODEL=gpt-5.6-terra
SENTINEL_WATCH_INTELLIGENCE_ALLOW_DESCRIPTION=false

# Keep both values below for ordinary Watch monitoring.
SENTINEL_WATCH_MONITOR_ONLY=true
SENTINEL_WATCH_AUTO_RESPONSE_ENABLED=false
```

Do not enable automatic response until shadow replay and real pilot traffic show an acceptable
false-positive rate for each detector/policy pair.

