# SentinelGate taint and lineage model

SentinelGate tracks information flow across a whole agent trace, not only a single HTTP
request. Each input and connector output receives signed provenance containing its tenant,
trace, trust, classification, labels, content digest, lineage ID and parent lineage IDs.

## Monotonic propagation

For every tool result SentinelGate computes:

- the least-trusted input trust level;
- the highest input or output data classification;
- the union of all inherited and newly detected taint labels;
- a new signed output-provenance token linked to its parents.

Trust can become weaker, classification can become stronger and labels can accumulate. A
later tool cannot declare data cleaner than its ancestors. Signed tokens are bound to a
tenant and trace and are rejected if replayed into another trace.

## Server-side trace memory

The gateway stores the conservative trace summary. Every later decision automatically
includes that summary even when an agent omits a previous output-provenance token. This
prevents simple provenance laundering by dropping application-side context.

## Sink enforcement

Each tool policy may define:

- `max_input_classification`: the strongest classification accepted by the tool;
- `classification_violation`: `deny` or `require_approval`;
- `blocked_taint_labels`: labels that always prevent the transition;
- `sensitive`: whether untrusted input is prohibited;
- `require_provenance`: whether unsigned context is rejected.

The included email policy rejects `confidential` or `restricted` flows and labels such as
`prompt_injection`, `secret`, `customer-data` and `restricted`. These values are examples;
operators must set them for their own data handling rules.

## Connector contract

A connector returns both its result and security metadata: classification, trust, labels and
source identifiers. Connector metadata is validated before signing. Unknown or malformed
classification, trust or label metadata fails closed as `restricted` and `untrusted`.

The bundled knowledge connector is intentionally read-only and bounded. The GitHub App
connector implements the same result contract with repository-scoped short-lived credentials.
Future Slack, database or email connectors must not hold broader credentials than their
individual task requires.

## Boundaries

This mechanism is deterministic information-flow control, not proof that a model understood
content safely. It cannot protect tools called outside SentinelGate, identify every possible
secret or prompt injection, or undo information that was already revealed before deployment.
Trace state currently lives in SQLite and should move to a transactional shared store before
multi-instance production use.
