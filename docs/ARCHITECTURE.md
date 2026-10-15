# SentinelGate architecture

## v0.16 product surfaces

SentinelGate presents three operational surfaces over one control plane:

- **Gate** is the inline authorization and information-flow enforcement point.
- **Watch** correlates versioned task/session metadata and produces explainable findings.
- **Watch+** adds selective evidence-bound LLM analysis, flight records, replay and bounded
  interventions. Model output never receives execution authority.

The public website can run as the separate `sentinelgate.marketing:app` process, which has no
control-plane routes or credentials. Authenticated operations live in `sentinelgate.api:app`.
The API remains the authority; the browser never makes a policy decision.

MCP manifest inspection is both an administrative pre-connection control and an inline upstream
gate. A clean tool definition is hashed and stored as a baseline. Configured upstream manifests
are refreshed before each call; changed or poisoned definitions are refused before the remote
tool executes. Injection-shaped content, hidden controls and duplicate declarations remain
blocking even when baseline replacement is requested. Cross-server name collisions require review.

Security evidence reports summarize tamper-evident operational records. Their control mapping
helps pilot and audit review, but is deliberately not represented as a compliance certification.

SentinelGate is an enforcement point, not a model-side instruction. An application must
route every custom tool call through the gateway and execute tools only when the gateway
returns `succeeded`.

## Watch and Watch+ boundary

SentinelGate Watch is an observational subsystem, not a second policy engine. Gate decisions feed
metadata-only call events into Watch after the decision is finalized. Runtimes may additionally
submit explicit progress, result, token and estimated-cost events with a scoped agent identity.

Watch applies fixed, reviewable thresholds to each tenant-and-agent-bound task. Findings contain a
code, severity, confidence, evidence and recommended response. Watch+ LLM analysis operates only
on bounded metadata, validates cited event IDs and produces advisory findings. It cannot approve
or execute a plan. Human response requires one authenticated decision and a second explicit
execution request. An administrator may separately enable a deterministic, high-confidence,
task-pause-only policy; model findings are never eligible. Task recovery and session-level token
revocation require an authenticated approver.

The flight recorder is a joined view over task metadata, ordered schema-versioned events,
findings and response plans. It records an event digest and audit-chain result, but deliberately
does not store prompt bodies or raw tool arguments.

## Request path

1. The application authenticates with a short-lived agent token.
2. External or retrieved content is attested with its tenant, digest, trust level,
   classification, taint labels and injection signals.
3. The proposed tool call enters the gateway with its provenance tokens and trace ID.
4. SentinelGate checks token revocation, active containment, rate limits, provenance,
   field-specific flow policy, agent allowlists, scopes, schema, DLP, egress budget and recent
   sequence state.
5. The call is denied, held for exact human approval, or executed once through the
   code-owned registry.
6. Tool output is scanned, classified, signed and linked to its parent lineage before it
   is returned to the agent.
7. The server aggregates trace taint independently of agent-supplied tokens, preventing
   a later call from laundering data by omitting provenance.
8. The decision and action metadata enter the HMAC-linked audit log, lineage graph and
   activity timeline.
9. Egress bytes are reserved only after a call is authorized and wins the one-time execution
   claim, so pending or rejected approvals cannot exhaust another call's quota.

## GitHub connector boundary

The GitHub connector authenticates as a GitHub App, then mints an installation token narrowed
to the requested repository and minimum permission set. The code fixes the API origin to
`api.github.com`, refuses redirects, ignores ambient proxy configuration, requires an explicit
repository allowlist and applies bounded argument schemas before any network call.

Read operations return security metadata as well as content. Issue text is untrusted external
content; repository source is internal. Signed output provenance carries that distinction into
later actions. Write operations require exact approval, cannot target `main` or `master`, and
cannot modify `.github/workflows` or common secret-bearing files.

## Rollout and replay

`observe` evaluates and records mirrored calls without invoking a connector. `warn` executes
allowed calls but labels unsafe attempts as blocked warnings. `enforce` applies normal policy
and approvals. None of the modes converts a deny into an unreviewed side effect.

Normal evaluations create encrypted snapshots containing the call, principal scopes,
security findings and provenance summary. The replay engine runs those snapshots through an
active or proposed deterministic policy without connector calls, rate-limit changes,
approvals, quarantine or other side effects.

## MCP surface

The `/mcp` endpoint implements stateless JSON-RPC initialization, ping, tool listing and tool
calls. Tool definitions come from the same code-owned Pydantic schemas as the REST executor,
and discovery is filtered by agent identity and scopes. MCP does not create an alternative
authorization path: every call becomes a normal `ToolCallRequest` and uses the same policy,
lineage, approval, execution and audit pipeline.

For an operator-configured upstream, `/mcp/upstream/{server_id}` performs discovery, integrity
inspection and runtime schema registration before exposing tools. Every `tools/call` repeats
discovery before it is rewritten to a server-bound internal tool. The ordinary REST execution
endpoints reject caller-supplied MCP bindings, preventing an agent from skipping the refresh path.

## Information-flow model

Classifications are monotonic within a trace: `public < internal < confidential < restricted`.
Trust is also conservative: `trusted < mixed < untrusted`. A derived tool output inherits
the strongest classification, least-trusted source and union of all parent labels. Sink
policies can reject specific labels or any classification above their configured maximum.

Structured provenance additionally binds metadata to individual JSON leaves. Deterministic
derivations are recomputed before signing. Because arbitrary model transformations cannot be
proven semantically, their output receives the conservative union of every supplied input.

Recent lineage is also aggregated per tenant and agent for a bounded window. This prevents an
agent from immediately washing taint away with a new trace ID, at the cost of possible temporary
over-taint across genuinely unrelated tasks.

The included knowledge connector reads only `.md` and `.txt` files below the configured
root, rejects symlinks and oversized files, and returns bounded snippets. Document front
matter controls `classification`, `trust`, and comma-separated `labels`.

## Bounded containment

| Mode | Effect | Reversible? |
|---|---|---|
| `monitor` | Records a time-bounded heightened-observation state without blocking | Yes |
| `restrict` | Allows only the explicitly named tools | Yes |
| `quarantine` | Blocks every tool call for the containment duration | Yes |
| `revoke` | Revokes all current agent tokens and blocks calls | Tokens remain revoked |

Containments expire automatically. An administrator may release them early. Revoked
credentials do not become valid again when a containment is released; issue a new token
after review. The gateway never changes unrelated cloud, endpoint or identity systems.

## What the MVP deliberately does not do

- It does not inspect OpenAI-hosted tools that bypass the application tool loop.
- It does not claim semantic prompt-injection detection is complete.
- It does not autonomously remediate arbitrary infrastructure.
- It can federate administrator authentication to OIDC but does not replace the customer's
  identity provider, distributed database, KMS or SIEM.
- Its MCP endpoint is not yet fully conformant with the modern stateless MCP 2026-07-28
  lifecycle, MRTR, extensions and OAuth hardening requirements.

These constraints make failure modes legible and keep containment bounded.
