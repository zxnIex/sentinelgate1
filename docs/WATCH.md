# SentinelGate Watch Alpha (v0.11 legacy)

This document describes the v0.11 compatibility surface. New integrations should use
[`WATCH_BETA.md`](WATCH_BETA.md), event schema 1.0 and the Gate/Watch/Respond workflow.

Watch detects signs that an agent task is stuck, looping, retrying or exceeding an explicit budget.
It complements SentinelGate Core; it does not replace the firewall or authorize an action.

## Authority boundary

| Component | May decide tool calls | May execute tools | May contain agents |
|---|---:|---:|---:|
| SentinelGate Core | Yes | Through its bounded registry | Through authenticated operator/API controls |
| SentinelGate Watch Alpha | No | No | No; recommends review only |

Production settings enforce `SENTINEL_WATCH_MONITOR_ONLY=true`. A Watch failure is recorded in the
Core audit chain and does not change the action decision.

## Signals

Profiles use fixed thresholds over a five-minute window:

| Signal | Strict | Balanced | Relaxed |
|---|---:|---:|---:|
| Identical call fingerprints | 4 | 6 | 10 |
| Repeated identical errors | 3 | 5 | 8 |
| Repeated denied calls | 3 | 4 | 6 |
| Poll/status-like calls | 8 | 12 | 20 |
| Repeated call-cycle | 3 | 3 | 4 |
| No explicit progress | 10 min | 15 min | 30 min |

Task-specific runtime, tool-call and estimated-cost budgets are configured when the task is created.
An explicit `progress` event creates a new phase for repetition and cycle detection.

## Data minimization

Automatic observation stores:

- tenant, agent, task and event identifiers;
- tool name and Core decision;
- deployment-keyed HMAC-SHA-256 fingerprint of the canonical tool name and arguments;
- bounded error/reason code and timestamps.

It does **not** store raw prompts or tool arguments. Explicit telemetry also supports numeric token,
duration and estimated-cost fields. Do not place secrets, prompts or customer content in
`progress_signal`, `outcome` or `error_code`.

## API integration

Issue an agent token containing `watch:write`, then create a task:

```http
POST /v1/watch/tasks
Authorization: Bearer <agent-token>
Content-Type: application/json

{
  "task_id": "deploy-1842",
  "description": "Check deployment and summarize the result",
  "profile": "balanced",
  "max_runtime_seconds": 1800,
  "max_tool_calls": 80,
  "max_cost_usd": 2.00
}
```

Report a milestone or model/connector result:

```http
POST /v1/watch/events
Authorization: Bearer <agent-token>
Content-Type: application/json

{
  "task_id": "deploy-1842",
  "event_type": "progress",
  "outcome": "deployment_found",
  "progress_signal": "phase_one_complete",
  "input_tokens": 4200,
  "output_tokens": 600,
  "estimated_cost_usd": 0.018
}
```

If tool calls already pass through SentinelGate, include the same `task_id` on each
`ToolCallRequest`; the gateway observes those decisions automatically. If omitted, Watch uses the
trace ID as the task boundary.

Operators can use:

- `GET /v1/watch/summary`
- `GET /v1/watch/tasks`
- `GET /v1/watch/tasks/{task_id}/events`
- `GET /v1/watch/findings`
- `POST /v1/watch/findings/{finding_id}/status`
- `/console/watch`

Acknowledging or resolving a finding changes review state only. To contain an agent, an authorized
operator must separately call the existing Core containment API.

## Honest limits

Watch Alpha is deterministic metadata analysis. It cannot reliably detect semantic repetition after
arbitrary paraphrasing, infer whether a task is truly successful, or distinguish every legitimate
retry from a broken loop. The included simulator is a project-authored regression suite, not an
independent efficacy benchmark.
