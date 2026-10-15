# SentinelGate Watch Beta

Watch Beta is the detection layer between Gate decisions and Respond actions. It consumes
metadata, not prompt bodies or tool arguments, and emits deterministic findings with evidence.

## Event contract

Every stored event uses `schema_version: "1.0"`. For v0.11 client compatibility, omission is
normalised to `1.0`; any explicit unknown version is rejected. The canonical JSON
Schema is [`schemas/watch-event-v1.schema.json`](../schemas/watch-event-v1.schema.json) and the
running control plane exposes the same Pydantic contract at `GET /v1/watch/schema/event`.

`task_id` identifies the business task. `session_id` identifies one runtime attempt or thread.
They are deliberately separate: a task may survive a process restart, while two unexpected
sessions claiming a single-session task is itself evidence.

Use `milestone_id` for stable success-criterion identifiers. Human-readable `progress_signal`
may change without breaking completion checks.

## Deterministic detectors

- identical repeated calls;
- retry storms and repeated Gate denials;
- exact and tool-shape cycles;
- excessive polling and no-progress windows;
- runtime, call and reported-cost budget breaches;
- tools outside `expected_tools`;
- multiple sessions on a single-session task;
- repeated milestones;
- activity after a terminal task state;
- completion without required success criteria.

Threshold profiles remain explicit and replayable. `POST /v1/respond/replay` compares historical
tasks against a candidate profile without writing findings or executing tools.

## OpenTelemetry ingestion

`POST /v1/watch/otel/v1/spans` accepts a privacy-minimised GenAI span subset. SentinelGate reads
task/conversation identifiers, tool name, status, duration and token counts. It does not accept or
persist prompt content, completion content, tool arguments or tool results through this endpoint.

## Respond boundary

Watch may persist a proposed bounded intervention. An approver must first decide the plan through
`POST /v1/respond/plans/{id}/decision`; execution is a separate call to
`POST /v1/respond/plans/{id}/execute` and is allowed only for an approved, unexecuted plan.

Supported actions are deliberately narrow: review, pause one task, restrict an agent to the
task's declared tools, or temporary quarantine. Watch itself has no execution authority.

## Evaluation

Run:

```powershell
python -m sentinelgate.watch_evaluation `
  --output evidence\watch-beta-v0.14.json
```

The suite contains 120 scripted workflows: 90 development and 30 held out. Tool calls traverse
`GatewayService`; connector-result and progress metadata use the same Watch API models used by
runtimes. Reports include the confusion matrix, precision, recall, false-positive rate, detection
delay, actual monitor-only cost after detection and a separately labelled counterfactual.

This is project-authored regression evidence. The held-out partition is not externally selected,
and the result must not be advertised as independent validation.
