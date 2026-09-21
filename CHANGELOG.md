# Changelog

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
