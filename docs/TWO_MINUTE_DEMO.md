# Two-minute SentinelGate demonstration

## Purpose

Show a single unsafe transition being stopped at the tool boundary. This is a product demonstration, not an efficacy benchmark.

## Presenter script

**0:00–0:20 — Establish the boundary**

“The agent can reason freely, but every sensitive tool call must pass through SentinelGate. The agent proposes an action; it does not execute with raw connector credentials.”

**0:20–0:45 — Introduce untrusted content**

Run the hostile onboarding scenario. Explain that the external webpage contains instruction-shaped content and is attested as untrusted. The raw content is scanned in memory; durable evidence stores its digest and signals.

**0:45–1:10 — Show propagation**

Open Data flows. Point to the source and the `/body` field lineage. Explain that field-level provenance prevents the safe recipient field from being treated identically to the influenced message body.

**1:10–1:35 — Attempt the sensitive action**

Show the proposed external email. State clearly that the email connector in the included demo is simulated. The important event is the policy decision before execution.

**1:35–1:50 — Show the denial**

Point to the deny effect and deterministic reason code. Explain that prompt-injection detection is a signal; identity, provenance and sink policy form the boundary.

**1:50–2:00 — State the limitation**

“If an agent possesses direct tool credentials and bypasses this gateway, SentinelGate cannot protect that call. This release is project-authored and has not been independently validated.”

## Pass conditions

- the safe knowledge read is allowed;
- the hostile egress is denied or held for approval according to the checked-in policy;
- both decisions appear in the audit view;
- the hostile trace shows its source, field labels, sink and reason code;
- no real email is sent.
