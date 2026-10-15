# Public SaaS release gates

This checklist is deliberately evidence-based. A code change cannot mark external work complete.

| Gate | Repository evidence | External evidence required | Status |
|---|---|---|---|
| Cross-tenant authorization | Membership model, session/CSRF tests, fail-closed legacy routes | Independent tenant-isolation review; every operator route tested | Partial |
| Account lifecycle | OIDC sync, invites, logout, deactivation, deletion request/cancel | Support, ownership-transfer and final-erasure drills | Partial |
| Legal | Versioned acceptance records | Approved terms, privacy/cookie notice, DPA and jurisdiction review | External blocker |
| Billing | Stripe Checkout/portal/webhook code and idempotency | Live product/tax/refund/invoice tests and accounting review | External blocker |
| Operations | Readiness, metrics, outbox, worker, PostgreSQL tooling | Hosted failover/restore, alerts, incident and on-call drills | External blocker |
| Security assurance | Automated regression, red-team and dependency scans | Independent penetration test and remediation verification | External blocker |
| Product evidence | Local and project-authored benchmarks | Design-partner integration, false-positive and bypass data | External blocker |

No public launch should occur while any external blocker remains unresolved. Keep a dated evidence
link beside each completed gate rather than treating this file as self-certification.
