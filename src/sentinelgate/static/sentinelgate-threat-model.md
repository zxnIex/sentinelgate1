# SentinelGate threat model

Version: 0.17.0  
Status: design-partner and SaaS-boundary preview; project-authored, not independently validated

## Security objective

Prevent an autonomous agent from using mediated tools outside its delegated authority, and retain enough provenance and audit evidence for an operator to understand the decision.

## Protected boundary

The protected path is:

`agent -> authenticated SentinelGate API -> policy/provenance evaluation -> controlled executor -> configured tool`

Calls made directly to a tool, with credentials unavailable to SentinelGate, are outside the boundary.

## Assets

- agent and administrator credentials;
- tool arguments and connector output;
- provenance attestations and field lineage;
- policy and MCP definition baselines;
- approvals and execution claims;
- audit records and encryption/signing keys;
- connector and upstream credentials.

## Trust boundaries

1. External content entering the agent is untrusted or mixed-trust data.
2. The agent is authenticated but not trusted to grant itself permissions, provenance or declassification.
3. The gateway process is trusted to evaluate policy and protect key material in memory.
4. Connectors, MCP servers, identity providers and notification destinations are external dependencies.
5. Administrators are powerful trusted operators; compromise of an authorised administrator is not fully contained.

## Threats and controls

| Threat | Principal controls | Residual risk |
|---|---|---|
| Indirect prompt injection | provenance, field taint, sink policy, sequence rules | novel semantic influence may evade content signals |
| Excessive agent privilege | scoped expiring identity, tenant binding, revocation | incorrect scope configuration remains possible |
| Sensitive-data exfiltration | field labels, DLP, egress limits, sink policy | encoded or transformed secrets may evade deterministic detection |
| Approval mutation or replay | canonical request binding, expiry, single execution claim | compromised approver may authorise a harmful exact request |
| MCP definition poisoning | description/schema inspection, baseline drift check before call | unsupported transports and malicious but superficially benign semantics |
| Confused deputy | principal-bound policy and connector allowlists | incorrect connector implementation or policy can reintroduce risk |
| Audit tampering | HMAC-linked audit chain | host/key compromise can undermine local evidence |
| Notification loss | transactional outbox, leases, retries, dead-letter state | external destination outage may delay review |
| Database races | transactions, locks and PostgreSQL integration races | managed failover and extreme-load behaviour require deployment testing |
| SSRF and hostile upstreams | configured upstream allowlists and bounded responses | full MCP discovery/OAuth is not yet implemented |
| Billing entitlement forgery | hosted checkout, signed timestamped webhooks, server-side catalogue, event idempotency | exact concurrent usage accounting is not yet a financial ledger |
| LLM analysis error or injection | metadata-only input, strict schema, evidence-ID validation, advisory-only authority | semantic false positives and false negatives remain possible |
| Unsafe automatic response | disabled by default, deterministic-only named policies, task-pause-only action, approved recovery | an incorrect enabled policy can still interrupt a legitimate task |

## Explicit non-goals

- protecting direct tool calls that bypass SentinelGate;
- proving semantic non-interference through arbitrary LLM transformations;
- malware detection, endpoint response or general SOC automation;
- guaranteeing external service availability;
- providing a compliance certification;
- claiming external validation or independent penetration testing.

## Operational assumptions

- production uses PostgreSQL and federated administrator identity;
- TLS terminates at a controlled trusted boundary;
- secrets are supplied through an approved secret store or protected mount;
- agents do not retain unmediated connector credentials;
- policies are reviewed and changes are auditable;
- backups, restoration and incident response are exercised in the chosen environment.

## Known release limitations

- bounded stateless JSON-RPC MCP rather than full Streamable HTTP/SSE/OAuth;
- limited connector coverage;
- project-authored adversarial corpus;
- no independent penetration test or production customer evidence;
- no direct cloud-KMS envelope encryption;
- managed database failover has not been certified by this repository.
- shared public-SaaS tenant isolation has not completed exhaustive route-level authorization testing;
- pricing and willingness to pay have not been validated with customers.

## Validation priorities

1. Integrate one disposable real agent workflow.
2. Record installation time, bypasses and false positives.
3. Exercise PostgreSQL backup/restore and concurrent workers.
4. Submit the architecture and test environment to an external reviewer.
5. Retain failures and unsupported cases in published evidence.
