# SentinelGate security model

## Status

SentinelGate 0.7 is a security-focused design-partner MVP. It has automated tests and static/dependency scanning, but it has not received an independent audit and must not be represented as certified or production-hardened.

## Assets protected

- Credentials and sensitive values passed through agent tools
- External side effects such as messages and mutations
- Tenant and agent authorization boundaries
- Integrity of approval requests
- Integrity and reviewability of security decisions

## Trust boundaries

1. The language model is untrusted for authorization decisions.
2. Agent content is not trusted merely because a model processed it.
3. Tool arguments are validated again by SentinelGate.
4. Normal agents cannot mint trusted provenance.
5. The administrator and configured tool handlers are privileged.
6. The host, process memory and local encryption keys are inside the current trust boundary.

## Enforced invariants

1. Unknown tools fail closed.
2. Agent and tenant identity come from a signed token, not the request body.
3. Tool execution requires both an agent allowlist match and every required scope.
4. Sensitive tools require signed provenance.
5. Untrusted provenance cannot directly trigger a sensitive tool.
6. Prompt-injection heuristics can deny or escalate; they can never grant access.
7. Egress containing detected credentials is denied.
8. Tool arguments reject missing, malformed and unexpected fields.
9. Human approval is bound to the canonical request hash and expires.
10. Approval consumption and request execution are at most once.
11. Approval payloads are authenticated-encrypted at rest.
12. Audit payloads redact known secret values.
13. Repeated high-risk denials can quarantine an agent; release is administrative and audited.
14. Production refuses weak, example or reused application secrets.
15. Issued agent tokens are registered and can be revoked immediately.
16. Egress tools are bounded by per-action and rolling-hour byte budgets.
17. Containment is time-bounded, mode-specific and administratively auditable.
18. Connector outputs receive signed lineage and inherit parent taint monotonically.
19. Server-side trace state prevents an agent from clearing taint by omitting output provenance.
20. Egress sinks enforce maximum classifications and blocked taint labels.
21. GitHub installation tokens are narrowed to one allowlisted repository and the required permission set.
22. GitHub writes cannot directly target `main`, `master`, workflow files or common secret paths.
23. Observe mode never invokes connector handlers.
24. Policy-replay snapshots are authenticated-encrypted and never execute tools.
25. Clean MCP tool definitions are hashed; silent definition changes fail closed until explicit review.
26. Instruction-shaped or hidden-control MCP definitions cannot be accepted through the baseline override.
27. Configured upstream MCP definitions are refreshed and enforced before each remote tool call.
28. Egress quota is reserved only at the one-time execution boundary.
29. A fresh trace identifier does not clear recent agent taint inside the configured window.

## Attacker model

The MVP anticipates:

- malicious instructions embedded in webpages, documents, emails or RAG records;
- a model proposing an unauthorized or malformed tool call;
- an agent attempting to exfiltrate recognizable credentials;
- confused-deputy attempts across agents or tenants;
- request replay and approval-record modification;
- bursts of repeated high-risk actions.

## Known limitations

### Deployment and identity

- Local HS256-style workload tokens are for the MVP. A production deployment should validate enterprise workload identities using asymmetric keys and rotation.
- The static admin bearer token has no individual administrator identity or MFA.
- Revocation is local to the SQLite control plane; distributed deployments require a shared, strongly consistent store.
- SQLite and in-process locks are designed for one application process, not a distributed cluster.
- Quarantine and rate limiting are local to the SQLite deployment.

### Provenance

- SentinelGate retains taint within a trace and conservatively carries recent agent taint across
  trace identifiers for a configurable window (15 minutes by default). This reduces trace-reset
  laundering but may temporarily over-taint unrelated work; stable task traces are still required.
- Pattern-based injection signals are incomplete and can produce both false positives and false negatives.
- Content digests prove which content was attested only when the surrounding ingestion pipeline also verifies the digest.

### DLP

- DLP covers selected credential formats and sensitive key names, not all secrets, personal data, intellectual property or encoded/encrypted content.
- Output scanning occurs after a tool handler runs. It prevents returning detected secrets to the model, but it cannot undo side effects already performed by that handler.
- Fingerprints reduce log exposure but may still reveal equality relationships between repeated secrets.

### Execution

- Only calls routed through SentinelGate are protected. Direct calls, OpenAI-hosted tools or alternative execution paths can bypass it.
- The knowledge connector performs bounded local reads. The GitHub connector performs real
  network reads and approval-bound writes when configured. Email and customer connectors
  remain simulated.
- The GitHub connector supports GitHub.com only, runs in the API process and has not been
  independently audited. Production should isolate it in a separately permissioned worker.
- MCP uses the SentinelGate agent bearer token and a stateless JSON-RPC subset. Configured HTTP
  upstreams are discovered and proxied inline, but full Streamable HTTP sessions, SSE delivery,
  binary content, MCP OAuth discovery and arbitrary agent-selected servers are not supported.
- Upstream MCP configuration is operator-owned and loaded in-process. Changes to endpoint or
  authorization configuration require a process restart; manifest definitions are refreshed per call.
- Tool policy and code registration can drift; production requires signed policy releases and deployment checks.

### Audit and storage

- The HMAC chain reveals modification when verified, but a host administrator holding the key can rewrite the entire chain. Export and externally anchor events for stronger guarantees.
- AES-GCM protects stored approval payloads only while the data-encryption key remains separate from the database.
- AES-GCM also protects policy-replay snapshots, which may contain exact tool arguments. Disable
  collection or apply an appropriate retention policy before processing regulated data.
- SQLite data is not otherwise encrypted by SentinelGate.

### Automated response

- Quarantine can be abused for denial of service. Thresholds must be tuned, and production should use richer signals and staged containment.
- `monitor` and `restrict` are gateway states only; they do not alter external identity-provider or cloud permissions.
- Releasing a `revoke` containment does not resurrect revoked credentials.
- SentinelGate does not autonomously change arbitrary infrastructure or remediate general cyber incidents.

## Safe deployment baseline

- Terminate TLS in front of the service and do not expose it directly to the public internet.
- Use four distinct random values for admin authentication, audit signing, workload-token signing and data encryption.
- Store secrets outside the image and repository.
- Run one worker with SQLite; migrate before scaling horizontally.
- Restrict outbound network access from connectors.
- Give each agent only the scopes it requires.
- Give `provenance:attest:trusted` only to a hardened ingestion identity.
- Export metrics and audit events to a separate security system.
- Back up the database and test restoration.
- Run the test, adversarial, static-analysis and dependency-audit commands before deployment.

## Reporting a security issue

Do not publish a suspected vulnerability with live secrets, customer data or an operational exploit. Report it privately to the project owner with the affected version, reproduction steps, expected impact and a minimal proof of concept.
