# SentinelGate

> v0.10 is a developer-preview/design-partner release, not an independently validated
> enterprise-production claim.

SentinelGate is an identity-aware, fail-closed security gateway for custom tools used by autonomous AI agents. It mediates an action before application code executes it and returns one of three outcomes: `allow`, `deny`, or `require_approval`.

Version 0.10 is a tested design-partner release—not a claim of production certification. Its narrow promise is:

> Prevent unauthorized agent tool execution and unsafe information flow while preserving reviewable evidence for every decision.

## What v0.10 adds

- Guided browser onboarding: validate the deployment, issue one scoped agent token and run both a
  safe and hostile call through the gateway.
- A rebuilt responsive control plane with an animated live decision gate, benchmark evidence and
  database/worker/queue health.
- Optional browser SSO using the OIDC authorization-code flow with PKCE. Operator authorization
  still uses the customer's existing roles; SentinelGate does not maintain local enterprise users.
- Durable approval notifications through a PostgreSQL/SQLite outbox worker with retries,
  deduplication, leases, dead-letter state and observable heartbeats.
- PostgreSQL concurrency tests in CI, authenticated Prometheus latency/counter metrics, and bounded
  backup/verification/restore-drill tooling.
- Authenticated reviewer attribution: the server derives the reviewer from the verified operator
  identity instead of trusting a reviewer string supplied by the browser.

The release still does **not** provide independent validation, a completed penetration test,
customer deployment evidence, direct cloud-KMS cryptography, full MCP Streamable HTTP/SSE/OAuth,
or broad connector coverage. Those remain explicit gates rather than hidden marketing claims.

## Enforcement path

```text
OpenAI Responses API / MCP client
        |
 proposed function call
        v
signed agent identity -> scope check -> lineage + taint -> DLP -> policy
                                                        |         |
                                                        |         +-> deny
                                                        |         +-> approval
                                                        v
                                                bounded connector registry
                                                        |
                                                one-time execution
                                                        |
                                             output DLP + audit event
```

OpenAI's Responses API returns custom function calls to application code. SentinelGate belongs in that application-controlled execution path. It cannot protect a tool that developers execute around the gateway.

## Features selected for this product

### Agent firewall and permission manager

- Signed, expiring agent identities
- Persistent agent inventory with owner, scopes and active-token count
- Immediate revocation of every active token for an agent
- Tenant binding and per-tool scopes
- Agent allowlists and fail-closed unknown tools
- Strict server-side argument schemas
- Request rate limits and replay prevention
- Explicitly denied destructive tools

### RAG and indirect-injection boundary

- Signed provenance attestations bound to content digests and tenants
- `trusted`, `mixed`, and `untrusted` classifications
- Separate `provenance:attest:trusted` capability
- Deterministic injection signals
- Mandatory provenance for sensitive tools
- Direct untrusted-to-sensitive transitions denied
- Signed provenance for connector outputs, including parent lineage
- Monotonic trace-level taint that cannot be cleared by omitting a token
- `public`, `internal`, `confidential` and `restricted` classifications
- Per-sink maximum classification and blocked-taint policies
- Signed JSON-pointer field provenance bound to exact leaf-value digests
- Field-specific sink policy for trust, classification and labels
- Verified copy, concatenation, template and substring propagation
- Conservative all-input union for arbitrary LLM transformations
- Explicit, allowlisted and audited label declassification

### Real knowledge connector

- Read-only search over bounded Markdown and text documents
- Operator-defined classification, trust and labels in document front matter
- File-size limits, extension allowlisting, symlink refusal and path containment
- Result snippets rather than arbitrary filesystem access
- Included safe, confidential and intentionally poisoned test documents

Documents may declare connector metadata in a small front matter block:

```markdown
---
title: Customer Analysis
classification: confidential
trust: trusted
labels: customer-data
---
The governed document content begins here.
```

Set `SENTINEL_KNOWLEDGE_PATH` to the directory SentinelGate may read. The connector only
returns bounded snippets from `.md` and `.txt` files inside that root. See
[`docs/TAINT_MODEL.md`](docs/TAINT_MODEL.md) for propagation and sink-enforcement semantics.

### GitHub App connector

- GitHub App authentication rather than personal access tokens
- One-hour installation tokens narrowed to one repository and the permission needed for the call
- Mandatory operator repository allowlist
- Read issue and bounded UTF-8 file operations
- Approval-bound issue comments, branch creation, single-file commits and draft pull requests
- Connector-level refusal of secret-bearing paths, workflow mutations and direct writes to
`main` or `master`
- GitHub issue bodies treated as untrusted external content and incorporated into trace taint

The connector targets `api.github.com`; GitHub Enterprise Server is not silently accepted as
an arbitrary network destination. GitHub writes are real when the App is configured. The
email and customer connectors remain simulations.

Full setup and test instructions are in
[`docs/GITHUB_CONNECTOR.md`](docs/GITHUB_CONNECTOR.md).

Injection matching is a signal, not the security boundary. Identity, provenance, scopes and deterministic policy remain authoritative.

### Data-loss prevention

- Recursive input and output scanning
- Detection for private keys and common OpenAI, GitHub, AWS and bearer credentials
- Sensitive-field detection
- Fingerprints in logs instead of secret values
- Secret-bearing egress denied
- Per-action and rolling-hour egress byte budgets
- Tool output blocked before returning to the model when a secret is detected

### Exact human approval

- Approval is bound to a canonical request hash, tenant, agent and scopes
- Approval requests expire
- Approval records are AES-GCM encrypted at rest
- Approved requests can execute once
- Mutated, expired and replayed requests fail closed
- Current policy is checked again immediately before execution

### Observability and bounded response

- HMAC-linked tamper-evident audit chain
- Incident correlation by tenant, agent and trace
- Queryable action timelines and sensitive-read-to-egress sequence detection
- Prometheus-format metrics
- Operator control plane for agents, incidents, approvals and containment
- Interactive lineage inspector with trace-level trust, classification and taint
- Exact approval-payload inspection plus approve/execute and reject actions
- Automatic quarantine after a configurable burst of high-risk denials
- Time-bounded monitor, restrict, quarantine and revoke modes
- Manual, audited containment release and incident lifecycle updates
- Side-effect-free policy simulation and a built-in adversarial suite
- `observe`, `warn` and `enforce` rollout modes
- Encrypted historical decision snapshots and current/proposed-policy replay
- MCP-compatible stateless JSON-RPC discovery and tool invocation
- Connector health and repository-allowlist visibility in the control plane

### MCP tool-definition security

- Admin-authenticated inspection for MCP `tools/list` manifests
- Deterministic scanning of tool descriptions and input schemas for instruction-like content
- Hidden Unicode control-character detection
- Credential- and prompt-shaped schema-field warnings
- Duplicate names and cross-server name-collision detection
- First-seen clean baselines with fail-closed detection of later definition changes
- Explicit reviewed baseline replacement; poisoned manifests cannot be accepted through the override
- Audit evidence for every manifest inspection
- Inline proxying of configured stateless HTTP MCP servers
- Automatic `tools/list` discovery and refresh before each remote `tools/call`
- Policy-bound server identity so clients cannot self-assert a trusted MCP source
- Fail-closed refusal of blocked, changed, stale or uninspected tool definitions
- Bounded response bodies, JSON content-type enforcement and JSON-RPC ID matching
- Bounded `tools/list` cursor pagination

### Federated administrator identity

- Development-only shared-token mode for local evaluation
- OIDC issuer, audience, signature, expiry and role verification for deployments
- Existing Entra, Okta, Auth0 and other standards-compliant providers can supply identity
- Production configuration refuses shared-token-only administrator authentication
- Viewer, analyst, approver and administrator role tiers are mapped from provider claims

### Operational approvals

- Optional signed webhook delivery when a request requires approval
- Slack-compatible `text` plus structured identifiers, expiry, reason codes and console link
- No tool arguments or sensitive body content included in notification payloads
- Delivery success or failure recorded in the tamper-evident audit chain

### Product site, console and evidence

- Public, honest product site at `/` with the security boundary stated explicitly
- Multi-page operator console under `/console`
- Dedicated views for traces, approvals, identities, incidents, connectors, MCP security,
  policy replay, audit and reports
- Admin token held in browser `sessionStorage`, rather than persistent local storage
- JSON security-evidence export plus audit CSV, with control mappings and an explicit
  non-certification disclaimer

The firewall, agent IAM, RAG boundary, observability and bounded containment belong in the
same first product because they all operate on the same tool-call enforcement path. Model
supply-chain scanning, honeypots and generic endpoint SOC automation are intentionally kept
out of this build.

## Deliberately excluded

These were in the broader idea list but do not belong in the same first product:

- Model and dataset supply-chain scanning
- Generic AI SOC investigation across endpoint/network/cloud telemetry
- Honeypot infrastructure
- Autonomous remediation of arbitrary infrastructure
- A general AI penetration-testing platform

They can become integrations or separate products after the enforcement gateway has real design partners.

## Quick start

Requires Python 3.11 or later.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
cp .env.example .env
```

Replace all example secrets in `.env`. Generate separate values; do not reuse one key for multiple purposes.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Start the gateway:

```bash
uvicorn sentinelgate.api:app --reload
```

- API documentation: <http://127.0.0.1:8000/docs>
- Product website: <http://127.0.0.1:8000/>
- Operator console: <http://127.0.0.1:8000/console>
- Health check: <http://127.0.0.1:8000/health>
- Readiness check: <http://127.0.0.1:8000/ready>

Open `/console/onboarding` after signing in. It performs the shortest complete evaluation path:
environment checks, scoped identity issuance, an allowed knowledge read and a denied unknown-tool
attempt. The issued agent token is retained only in the current browser tab.

If `SENTINEL_APPROVAL_WEBHOOK_URL` is configured, start the durable delivery worker in a second
terminal:

```bash
python -m sentinelgate.worker
```

With Compose, use `docker compose --profile notifications up --build`. Approval creation commits
the notification job to the same database transaction boundary; the worker delivers it with a
lease, bounded retries and dead-letter state. The System health page exposes the queue and worker
heartbeat.

Run the complete reproducible evidence suite:

```bash
python -m sentinelgate.benchmark_suite --iterations 2000 --output evidence/benchmark.json
```

The ten-case deterministic suite is reported as regression conformance, not efficacy. v0.10 also
ships 100 adversarial probes and a live HTTP concurrency harness. See
[`docs/BENCHMARKING.md`](docs/BENCHMARKING.md). Integration guidance is in
[`docs/INTEGRATION.md`](docs/INTEGRATION.md), with database deployment in
[`docs/POSTGRESQL.md`](docs/POSTGRESQL.md).

The report includes local policy-path latency, corpus exact-match/detection/false-positive
rates, and deterministic connector-failure/concurrency checks. The bundled corpus is
project-authored and must not be presented as independent validation.

For public deployment, run `sentinelgate.marketing:app` as the internet-facing website and
keep `sentinelgate.api:app` private behind HTTPS and OIDC-aware access controls. `compose.yaml`
demonstrates this split: port 8080 is the public site and the control plane binds only to
localhost port 8000.

Paste the raw `SENTINEL_ADMIN_TOKEN` value into the operator console. Do not prefix it with
`Bearer`; the browser adds that authentication scheme itself. Restart Uvicorn after editing
`.env` so the process reloads the values.

For a company deployment, configure the OIDC issuer/audience/JWKS values plus the optional browser
authorization and token endpoints, client ID and client secret. The console then presents a
**Continue with company SSO** button and uses authorization code + PKCE. MFA and account lifecycle
remain with Entra, Okta, Auth0, Google Workspace or another standards-compliant provider.

Swagger's **Authorize** dialog exposes separate `AdminBearer` and `AgentBearer` entries.
Paste raw token values into them; Swagger adds the `Bearer` prefix. Use the admin token to
issue and manage identities, and an issued scoped agent token for provenance and tool calls.

### Enforcement modes

Set `SENTINEL_ENFORCEMENT_MODE` to one of:

| Mode | Behaviour |
|---|---|
| `observe` | Records the policy verdict but never invokes a connector. Use with mirrored traffic. |
| `warn` | Executes allowed calls; unsafe calls remain blocked and are returned as warnings. |
| `enforce` | Normal deny, approval and execution behaviour. This is the default. |

Observe mode is deliberately side-effect free. It is not a switch that permits actions the
gateway considers dangerous.

## Configure the GitHub connector

Create and install a GitHub App on selected repositories. Grant only the repository
permissions needed by the tools you intend to enable: Contents, Issues and Pull requests.
Download its RSA private key and keep it outside the repository. GitHub's installation tokens
expire after one hour; SentinelGate additionally requests a token for one repository and one
operation's permission set. See GitHub's
[installation authentication documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation).

```env
SENTINEL_GITHUB_APP_ID=123456
SENTINEL_GITHUB_INSTALLATION_ID=789012
SENTINEL_GITHUB_PRIVATE_KEY_PATH=C:/secure/sentinelgate-app.private-key.pem
SENTINEL_GITHUB_ALLOWED_REPOSITORIES=your-org/repository-one,your-org/repository-two
```

An empty allowlist denies every GitHub operation. Restart Uvicorn after changing these
values. Use **Verify GitHub connection** on `/console/connectors` (or
`POST /v1/connectors/github/verify`) to prove the installation token and repository access
work; a `configured` status alone only means values are present. A least-privilege coding-agent
identity can use scopes such as:

```json
[
  "tools:github:issues:read",
  "tools:github:contents:read",
  "tools:github:issues:write",
  "tools:github:contents:write",
  "tools:github:pull_requests:write",
  "provenance:attest"
]
```

### 1. Issue a least-privilege agent token

```bash
curl -X POST http://127.0.0.1:8000/v1/tokens/agents \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id":"research-agent",
    "tenant_id":"acme",
    "scopes":["tools:search","tools:email:send","provenance:attest"],
    "ttl_seconds":3600,
    "owner":"platform@example.com"
  }'
```

### 2. Attest the context used by the agent

Content from a webpage, email, retrieved document or user should be attested before it can influence a sensitive tool. Normal agents may issue `mixed` or `untrusted` attestations. Only a dedicated trusted ingestor should receive `provenance:attest:trusted`.

```bash
curl -X POST http://127.0.0.1:8000/v1/provenance/attest \
  -H "Authorization: Bearer YOUR_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_id":"user-request-42","content":"Email the report to me","trust":"mixed"}'
```

The raw content is scanned in memory. Audit records contain its digest and signals, not the content.

### 3. Execute through the gateway

```bash
curl -X POST http://127.0.0.1:8000/v1/execute \
  -H "Authorization: Bearer YOUR_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":"user-42",
    "tool_name":"send_email",
    "arguments":{"to":"owner@example.com","subject":"Report","body":"Attached report"},
    "provenance_tokens":["YOUR_PROVENANCE_TOKEN"],
    "purpose":"Send a requested report"
  }'
```

The email connector included here is intentionally simulated; no real email is sent.

### 4. Review and execute an approval

```bash
curl http://127.0.0.1:8000/v1/approvals?status=pending \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

curl -X POST http://127.0.0.1:8000/v1/approvals/APPROVAL_ID/approve \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reviewer":"security@example.com","note":"Destination and content checked"}'

curl -X POST http://127.0.0.1:8000/v1/approvals/APPROVAL_ID/execute \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## OpenAI demo

The demo uses custom function tools from the OpenAI Responses API, sets `store=False`, attaches mixed-trust provenance to the user's request and passes every function call through `/v1/execute`.

```bash
export OPENAI_API_KEY=...
export OPENAI_MODEL=gpt-5.6-luna
export SENTINEL_AGENT_TOKEN=...
python -m sentinelgate.openai_demo
```

The demo also loads these values from a local `.env` file. Variables set in the
launching shell take precedence over values in `.env`.

No API key is included in the repository. The automated test suite mocks the model boundary and does not spend API credits.

For application code, use `SentinelGateClient` as shown in
[`docs/OPENAI_INTEGRATION.md`](docs/OPENAI_INTEGRATION.md).

## MCP tool surface

`POST /mcp` supports the stateless JSON-RPC methods `initialize`, `ping`, `tools/list` and
`tools/call`. It uses the same agent bearer token as the REST API. Trace data travels in the
standard extensible `_meta` object:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "github_get_issue",
    "arguments": {"owner": "acme", "repo": "app", "issue_number": 42},
    "_meta": {
      "sentinelgate": {
        "trace_id": "task-42",
        "provenance_tokens": [],
        "purpose": "Investigate reported bug"
      }
    }
  }
}
```

The response puts model-visible data in `content` and `structuredContent`; the signed output
provenance token is returned in `_meta.sentinelgate`. The endpoint follows MCP tool schemas
but does not yet implement the full stateful Streamable HTTP/SSE transport or MCP OAuth
discovery. See the [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).

### Inline upstream MCP gateway

Configure operator-approved upstreams in `config/mcp_upstreams.json`. URLs must use HTTPS,
except local development may use `http://127.0.0.1` or `http://localhost`. Credentials are
referenced by environment-variable name and are never accepted from an agent request:

```json
{
  "servers": {
    "docs": {
      "url": "https://mcp.example.com/rpc",
      "bearer_token_env": "DOCS_MCP_TOKEN",
      "allowed_agents": ["research-agent"],
      "required_scopes": ["tools:mcp:docs"],
      "output_trust": "untrusted",
      "output_classification": "internal",
      "tool_overrides": {
        "publish": {"egress": true, "sensitive": true}
      }
    }
  }
}
```

Point the MCP client at `POST /mcp/upstream/docs`. SentinelGate refreshes `tools/list`, scans
and baselines every definition, exposes only accepted tools, validates arguments against the
upstream JSON Schema and re-runs discovery immediately before each call. Remote output is
tainted `untrusted` by default. Sensitive or egress tools default to approval plus provenance;
their policy may be tightened with `tool_overrides`.

This release supports bounded stateless JSON-over-HTTP upstreams. Stateful Streamable HTTP,
SSE and MCP OAuth discovery are intentionally not claimed.

### Approval notification webhook

```env
SENTINEL_APPROVAL_WEBHOOK_URL=https://hooks.slack.com/services/...
SENTINEL_APPROVAL_WEBHOOK_SECRET=a-separate-random-signing-secret
SENTINEL_CONSOLE_PUBLIC_URL=https://sentinelgate.internal.example
```

The payload contains the approval identity and summary, not the frozen arguments. Generic
receivers can verify `X-SentinelGate-Signature` as HMAC-SHA256 over the exact request body.
Review and one-time execution still happen through the authenticated console/API.

## Policy replay

The gateway keeps up to 5,000 authenticated-encrypted decision snapshots. Replay the most
recent calls against the active policy from the dashboard or API:

```bash
curl -X POST http://127.0.0.1:8000/v1/policy/replay \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"limit":100}'
```

Supply a complete `policy` object in the same request to test a proposed policy without
executing tools. Replay covers deterministic policy evaluation; it does not reproduce live
rate-limit counters, connector state or historical external systems.

## Containment

Create a 15-minute restriction that leaves only knowledge search available:

```bash
curl -X POST http://127.0.0.1:8000/v1/agents/acme/research-agent/contain \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode":"restrict",
    "reviewer":"security@example.com",
    "reason":"Investigating anomalous egress sequence",
    "duration_seconds":900,
    "allowed_tools":["search_knowledge"]
  }'
```

`revoke` invalidates every current token and is intentionally not undone by releasing the
containment. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the exact behavior of
each mode.

## Verification

```bash
python -m pytest --cov=sentinelgate
python -m sentinelgate.redteam
python -m sentinelgate.benchmark --iterations 2000
python -m ruff check src tests
python -m bandit -q -r src
python -m pip_audit -r requirements.txt
```

The local suite and the live HTTP harness are reported separately. The live harness defaults to
`/v1/execute`, so its allowed knowledge-read scenario includes connector execution; blocked and
approval-required calls stop before connector execution. Neither result is an SLA.

Release-host verification on Python 3.12: **88 tests passed, 2 PostgreSQL-only tests skipped, 81%
line coverage**, 11/11 red-team regressions passed, 4/4 resilience cases passed, Ruff and Bandit
passed, and `pip-audit` found no known vulnerabilities in the locked requirements. The
2,000-iteration local SQLite policy path measured **0.359 ms p50, 0.587 ms p95 and 0.721 ms p99**
at about **2,532.7 evaluations/second**.

The 200-request HTTP `/v1/execute` smoke run had zero HTTP errors. At concurrency 1 it measured
6.423 ms p50 / 83.106 ms p99; at concurrency 100 it measured 677.379 ms p50 / 890.196 ms p99.
That high-concurrency result is intentionally retained: it was a single Uvicorn process using
SQLite and is evidence of development-stack contention, **not** a PostgreSQL capacity claim. See
the JSON under `evidence/` and reproduce on the intended deployment.

## Docker

```bash
docker compose up --build
```

Create `.env`, set `POSTGRES_PASSWORD` and replace every example secret before retaining data or
allowing another machine to reach the service. Compose starts PostgreSQL, a private gateway and a
separate public marketing process. The optional `notifications` profile starts the durable worker.
The images run as a non-root user, drop Linux capabilities and use a named PostgreSQL volume.

## Main endpoints

| Endpoint | Authentication | Purpose |
|---|---|---|
| `POST /v1/tokens/agents` | Admin | Issue scoped workload token |
| `GET /v1/agents` | Admin | Inventory agents, scopes and active tokens |
| `POST /v1/agents/{tenant}/{agent}/revoke` | Admin | Immediately revoke active tokens |
| `POST /v1/provenance/attest` | Agent scope | Attest and scan context |
| `POST /v1/evaluate` | Agent | Evaluate without executing |
| `POST /v1/execute` | Agent | Evaluate and guarded-execute |
| `GET /v1/approvals` | Admin | Review pending actions |
| `POST /v1/approvals/{id}/approve` | Admin | Approve exact request |
| `POST /v1/approvals/{id}/execute` | Admin | Consume approval and execute once |
| `POST /v1/simulate` | Admin | Batch policy evaluation without side effects |
| `POST /v1/policy/replay` | Admin | Replay encrypted historical snapshots against a policy |
| `GET /v1/connectors` | Admin | Inspect connector configuration without exposing credentials |
| `POST /v1/connectors/github/verify` | Admin | Perform a live least-privilege GitHub read check |
| `POST /mcp` | Agent | MCP-compatible JSON-RPC discovery and guarded tool calls |
| `POST /mcp/upstream/{server_id}` | Agent | Refresh, inspect and mediate a configured MCP upstream |
| `GET /v1/incidents` | Admin | Correlated security incidents |
| `POST /v1/incidents/{id}/status` | Admin | Update investigation lifecycle |
| `GET /v1/activity` | Admin | Query agent action timelines |
| `GET /v1/traces` | Admin | List trace-level classification and taint summaries |
| `GET /v1/traces/{trace_id}/lineage` | Admin | Inspect signed input/output lineage nodes |
| `POST /v1/agents/{tenant}/{agent}/contain` | Admin | Apply bounded containment |
| `GET /v1/containments` | Admin | List active or historical containment |
| `POST /v1/containments/{id}/release` | Admin | Release reversible containment |
| `GET /v1/audit` | Admin | Audit events |
| `GET /v1/setup/status` | Admin | Readiness-guided onboarding checks |
| `GET /v1/system/status` | Admin | Database, worker, queue and runtime state |
| `GET /v1/benchmarks` | Admin | Versioned local evidence and claim boundary |
| `GET /metrics` | Admin | Prometheus counters and request histograms |

## What must change before production

- Federate workload identities with customer cloud identity or SPIFFE where local signed agent
  tokens are not sufficient.
- Validate PostgreSQL failover and recovery on the actual managed database product.
- Replace file-mounted key material with direct cloud-KMS envelope encryption and exercise rotation.
- Make the audit chain externally anchored or export to append-only storage.
- Isolate network connectors into separately permissioned workers.
- Validate distributed rate limiting and containment under multi-region failure modes.
- Add policy signing, change review and staged rollout.
- Add broader DLP classifiers with measured false-positive/negative rates.
- Complete MCP Streamable HTTP/SSE/OAuth interoperability and add customer-requested connectors.
- Obtain independent corpus review, penetration testing and real customer deployment evidence.
- Obtain independent penetration testing and a secure development process.
- Validate the product with real design partners before expanding the feature surface.

Read [SECURITY.md](SECURITY.md) for the threat model and remaining limitations.
