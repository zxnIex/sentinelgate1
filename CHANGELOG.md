# Changelog

## 0.17.0

- Added a safe installer and `sentinelgate init`, `doctor`, `serve`, `generate-policy`, and
  `snippet` commands.
- Added OpenAI Agents SDK, LangGraph/LangChain, Python, and generic MCP adoption surfaces with
  explicit dependency boundaries.
- Added a conservative tool-discovery policy compiler. Generated policy is review-required and
  never activated automatically.
- Added an in-console integration compiler and a complete protected OpenAI Responses example.
- Added privacy-minimised, allowlisted, explicit opt-in onboarding funnel telemetry; it is off by
  default and never records prompts, tool arguments, tokens, paths, email addresses, or secrets.
- Added configurable display branding while retaining stable package and API identifiers.
- Added a design-partner quickstart, demo recording script, and independent adoption test.
- Improved diagnostics for Python version, distinct secrets, Git tracking, policy validity, and
  running-gateway version.
- Secret rotation now preserves unrelated `.env` configuration such as GitHub and OIDC settings.

## 0.16.0

- Added local operator accounts derived from OIDC identity, organisations and tenant-bound
  memberships with viewer, analyst, approver, administrator and owner roles.
- Replaced browser access tokens in URL fragments/session storage with opaque, revocable,
  server-side sessions and double-submit CSRF tokens. Bearer access remains for integrations.
- Added versioned terms/privacy acceptance, email-bound single-use invitations, account
  deactivation, metadata inventory export and delayed, reversible tenant-deletion requests.
- Added atomic abuse limits for organisation creation and invitation creation/acceptance.
- Added a fail-closed shared-mode route allowlist. Legacy operator routes that have not completed
  explicit tenant review return `SHARED_SAAS_ROUTE_NOT_HARDENED` rather than risking data exposure.
- Added production checks requiring OIDC-only authentication, billing, PostgreSQL and approved
  non-draft legal-document versions for shared mode.
- Marked SentinelGate as a compatibility-only working name pending trademark/domain clearance.

This release does not supply legal documents, tax/accounting advice, live payment validation,
incident staffing, penetration testing or customer traffic. Shared mode is a boundary preview;
dedicated/self-hosted mode remains the supported pilot path.

## 0.15.0

- Reframed the commercial product as **Gate**, deterministic **Watch**, and intelligence/response
  **Watch+** while retaining the existing API paths for backwards compatibility.
- Added a versioned server-side plan catalogue, tenant subscription projection, usage snapshots,
  Gate Free's ten-agent allowance and feature/quota enforcement boundaries.
- Added Stripe-hosted subscription Checkout, customer portal sessions, signed webhook validation,
  durable event idempotency and server-selected price identifiers.
- Added opt-in Watch+ LLM analysis with strict structured output, metadata-only default input,
  event-reference validation, confidence limits and explicit advisory-only behavior.
- Added administrator-configured deterministic task-pause policies, session-level credential
  revocation and authenticated controlled task recovery.
- Split the website and console navigation into Gate, Watch and Watch+ with plan/usage visibility.

The prices are an unvalidated commercial hypothesis. LLM findings cannot execute interventions.
Shared public SaaS multi-tenancy, exact concurrent usage accounting and independent efficacy
validation remain explicit release gates.

## 0.14.0

- Reframed the product as three connected operational surfaces: **Gate** for inline
  enforcement, **Watch** for runtime detection, and **Respond** for bounded human-authorised
  action.
- Versioned Watch events as schema `1.0`, published JSON Schema, added session and milestone
  context, and rejected unknown event versions.
- Added deterministic detection for undeclared tools, activity after completion, missing
  success criteria, repeated milestones, unexpected multi-session ownership and tool-shape
  cycles with changing arguments.
- Added privacy-minimised OpenTelemetry GenAI span ingestion.
- Added per-agent shadow behavioural baselines and least-privilege scope recommendations;
  neither capability changes policy automatically.
- Added tamper-evident task flight recorders, side-effect-free Watch threshold replay and
  persisted bounded intervention plans.
- Intervention approval and execution are separate authenticated operations. Supported
  actions are limited to review, pause one task, restrict an agent to declared tools or
  temporary quarantine.
- High-risk Watch findings now use the durable outbox and existing signed webhook worker.
- Added a 120-workflow scripted-agent evaluation with 90 development and 30 held-out
  workflows, explicit confusion matrices, detection delay and a named waste counterfactual.

The v0.14 evaluation remains project-authored and is not independent validation. Watch does
not autonomously execute an intervention.

## 0.11.0

- Added SentinelGate Watch Alpha, a monitor-only task-behavior layer separated from Core
  authorization and containment authority.
- Added automatic gateway-call observation and scoped task/event ingestion APIs.
- Added deterministic findings for repeated calls, retry storms, repeated denials, excessive
  polling, cyclic workflows, no-progress windows and runtime/tool/cost budget overruns.
- Added progress boundaries so legitimate phased work does not accumulate false loop evidence.
- Added a Watch console for task timelines, evidence, acknowledgements and human-triggered Core
  containment recommendations.
- Added tenant/agent binding, metadata-only records, audit events, summary metrics and database
  migration support for Watch records.
- Added a versioned healthy/adversarial regression simulator with explicit non-efficacy language.
- Updated the locked PyJWT dependency from vulnerable 2.14.0 to 2.15.1.

Watch Alpha does not autonomously contain an agent and is not semantic proof that a task is safe,
stuck or malicious. Independent validation and real design-partner telemetry remain release gates.

## 0.10.1

- Added a public `/learn` technical tour with a clearly labelled explanatory attack-flow simulation.
- Added a PostgreSQL-first ten-minute local evaluation path and presenter-ready two-minute demo.
- Added a downloadable threat model and compact architecture overview.
- Added the technical-tour assets without changing SentinelGate's product or API identity.
- Kept security and benchmark limitations visible in the product experience.

## 0.10.0 — 2026-09-21

### Operational credibility

- Added a database-backed transactional outbox for approval notifications with deduplication,
  leases, bounded exponential retries, dead-letter state and worker heartbeats.
- Added a separate `python -m sentinelgate.worker` process and an optional Compose worker profile.
- Added PostgreSQL multi-instance integration tests for approval races, outbox claims and the
  tamper-evident audit chain; CI runs them against PostgreSQL 17.
- Added bounded PostgreSQL `backup`, `verify` and `restore-drill` commands with SHA-256 manifests.
- Added route-level Prometheus counters and latency histograms plus queue and worker metrics.
- Added authenticated setup, system-status, durable-work and benchmark-evidence APIs.

### Operator and developer experience

- Rebuilt the public site and multi-page control plane with an animated agent enforcement gate,
  reduced-motion support and responsive layouts.
- Added guided onboarding that checks the environment, issues a scoped agent identity, runs a
  safe call and a fail-closed hostile call, and shows an integration example.
- Added an evidence-aware benchmark page and a system-health page.
- Replaced inline JavaScript with packaged static assets and a stricter script CSP.
- Added optional OIDC authorization-code + PKCE browser login. Local shared-token access remains
  development-only; SentinelGate does not create a parallel enterprise password directory.
- Reviewer identity for approvals, declassification, incident actions and containment is now
  derived from the authenticated operator rather than trusted from request JSON.

### Benchmarking

- The HTTP harness now defaults to `/v1/execute`, so allowed knowledge calls include bounded
  connector execution while denied and approval-required scenarios stop before connectors.
- Results include server health/readiness, endpoint, transport, errors, process resources and the
  exact reproducible command.
- The million-request path remains opt-in and must run against an isolated PostgreSQL deployment.

## 0.9.0 — 2026-09-21

- Added PostgreSQL persistence with psycopg connection pooling; production now refuses SQLite.
- Added file-mounted secret inputs for managed secret-store/CSI deployments without claiming a
  cloud-specific KMS integration.
- Added PostgreSQL-backed Compose topology and `/ready` deployment readiness checks.
- Reclassified the original ten-case corpus as regression conformance rather than efficacy.
- Added 100 project-authored adversarial and benign probes with misses and false positives retained.
- Added a live HTTP load harness for direct-versus-gateway, concurrency, payload, decision, error,
  CPU and memory measurements.
- Added field-provenance support to the Python integration client and a design-partner runbook.
- Explicitly refused self-modifying policy; adaptive recommendations still require replay and review.

## 0.8.0 — 2026-09-21

- Added signed, value-bound JSON-pointer field provenance and field-specific sink policy.
- Added verified deterministic propagation for copy, concatenation, templates and substrings.
- Added conservative all-input taint union for arbitrary LLM transformations.
- Added allowlisted, reviewer-attributed and audited field-label declassification.
- Added optional OIDC administrator federation with strict issuer, audience, signature,
  expiry and role validation; production refuses shared-token-only administrator access.
- Added a versioned efficacy corpus reporting exact-match, attack-detection and benign
  false-positive rates with explicit non-independent scope.
- Added replay/approval concurrency and fail-closed MCP outage/malformed-response checks.
- Hardened MCP mediation with response bounds, content-type and request-ID validation,
  protocol-version headers and bounded cursor pagination.
- Added a separately deployable public marketing process so production need not expose the
  control-plane application as the company website.
- Fixed deterministic test isolation from configured GitHub credentials and guaranteed
  SQLite connection closure on Windows.

## 0.7.0 — 2026-09-21

- Added fail-closed mediation for configured stateless HTTP MCP upstreams: automatic
  `tools/list` discovery, definition baselining, schema registration and guarded `tools/call`.
- Wired MCP inspection observations into normal policy evaluation; blocked, review, stale and
  uninspected definitions can no longer be ignored by the execution path.
- Re-checks the upstream manifest immediately before every MCP tool call to stop definition
  rug pulls before the remote tool executes.
- Added a conservative per-agent taint window so switching trace identifiers does not
  immediately clear recently observed classification and taint labels.
- Moved egress reservation to the one-time execution boundary; denied, pending and rejected
  calls no longer consume the hourly budget.
- Added signed approval webhooks compatible with Slack incoming webhooks and generic receivers.
- Added live GitHub App verification and exposed configured MCP upstreams in connector status.
- Added a reproducible local policy-path latency/throughput microbenchmark with explicit scope.
- Added regression coverage for MCP enforcement, rug pulls, output taint, cross-trace taint,
  egress accounting, webhook minimization and live connector verification.

## 0.6.0 — 2026-09-21

- Added a public product website with an explicit protection boundary and design-partner positioning.
- Replaced the single-page dashboard with a responsive multi-page operator console.
- Added MCP tool-description and schema inspection for injection-shaped content and hidden controls.
- Added persisted clean baselines, rug-pull detection, duplicate detection and cross-server name-collision warnings.
- Added explicit reviewed baseline replacement while refusing poisoned definitions.
- Added current-policy inspection and an interactive proposed-policy replay lab.
- Added downloadable operational security-evidence reports and audit CSV with honest
  non-certification language.
- Added MCP integrity metrics and audit events.

## 0.5.0 — 2026-09-21

- Added a GitHub App connector with repository- and permission-scoped installation tokens.
- Added bounded issue/file reads and approval-bound comments, branches, file commits and pull requests.
- Refused secret paths, workflow modification, unallowlisted repositories and direct protected-branch writes.
- Added safe `observe`, `warn` and `enforce` rollout modes.
- Added authenticated-encrypted decision snapshots and policy replay.
- Added an MCP-compatible stateless JSON-RPC tool surface.
- Added connector status, enforcement status and policy replay to the dashboard.

## 0.4.0 — 2026-09-20

- Replaced the stub knowledge search with a bounded, read-only document connector.
- Added signed output provenance, four-level data classification and taint labels.
- Added server-side trace lineage so omitted provenance cannot launder prior data access.
- Added classification and label policies for external sinks.
- Added a multi-round stateless OpenAI tool loop with a stable trace identifier.
- Added trace/lineage APIs, dashboard inspection, and approval actions.

## 0.3.3 — 2026-09-20

- Fixed stateless OpenAI tool-call continuation when `store=False`.
- Loaded demo configuration from `.env` without overriding shell variables.
- Rejected non-canonical Base64 encodings in signed tokens.

## 0.3.2 — 2026-09-20

- Added distinct Swagger `AdminBearer` and `AgentBearer` security schemes.
- Documented the admin-token-to-agent-token bootstrap flow.

## 0.3.1 — 2026-09-20

- Isolated the production-defaults test from a developer's local `.env` file.
- Clarified that the operator console expects the raw admin token without `Bearer`.

## 0.3.0 — 2026-09-20

- Added persistent agent registry with owner, scopes, token inventory and immediate revocation.
- Added time-bounded `monitor`, `restrict`, `quarantine` and `revoke` containment modes.
- Added incident lifecycle updates and containment-to-incident linkage.
- Added per-action and rolling-hour egress byte budgets.
- Added sensitive-read-to-egress sequence detection by agent trace.
- Added queryable agent activity timelines.
- Added a reusable Python client for application and OpenAI tool loops.
- Replaced the raw JSON dashboard with an operator control plane.
- Expanded the suite to 34 tests with 85% line coverage.

## 0.2.0

- Added signed workload identity, signed provenance, DLP, one-time encrypted approvals,
  replay prevention, incident correlation, quarantine, audit-chain verification and metrics.
