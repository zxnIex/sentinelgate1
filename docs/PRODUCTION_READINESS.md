# Production-readiness gates

SentinelGate v0.9 is a design-partner release. Passing its automated suite is necessary but
not sufficient for an enterprise production claim.

## Implemented and testable

- OIDC administrator token verification with issuer, audience, signature, expiry and roles
- Scoped, expiring and revocable agent identities
- Value-bound field provenance and deterministic/LLM-conservative propagation
- Fail-closed policy, connector and MCP integrity controls
- One-time approvals and execution replay protection
- Tamper-evident audit events and encrypted approval/policy snapshots
- Local regression, adversarial-probe, latency, failure and concurrency evidence
- Separate public website and private control-plane processes
- PostgreSQL runtime with bounded connection pooling and a production fail-closed configuration gate
- File-mounted secret inputs compatible with managed Kubernetes/VM secret-store mounts
- Live HTTP concurrency/payload harness with client-observed latency, errors and resource reporting
- Separate regression and 100-case project-authored adversarial evidence with misses retained

## Required before a production claim

- Exercise PostgreSQL migrations, backup/restore, multi-instance races and failover in the target environment
- Validate the chosen managed secret-store/CSI integration and key-rotation procedure; file mounts
  are supported, but direct cloud-KMS envelope encryption is not claimed
- Add a durable background queue for notifications and connector work
- Run backup restoration and regional recovery exercises
- Run multi-instance load, race and failover tests against the production database
- Complete threat modelling, dependency/SBOM review and independent penetration testing
- Validate the attack corpus and false-positive set with external reviewers
- Deploy to design partners and measure bypasses, policy tuning and operational burden
- Establish incident response, retention, deletion and vulnerability-disclosure procedures

These are release gates, not features that can be truthfully marked complete by local code.
