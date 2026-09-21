# Design-partner integration

SentinelGate is placed at the application's tool-dispatch boundary. It cannot protect tools that an
agent can invoke through a second, unmediated path.

## Minimal integration

1. Deploy the private control plane and PostgreSQL.
2. Configure OIDC for operators and create a scoped agent token.
3. Replace the application's direct tool dispatcher with `SentinelGateClient.evaluate` or
   `SentinelGateClient.execute`.
4. Attest retrieved external content before it reaches an egress or sensitive tool.
5. Preserve one trace identifier across the complete agent task.
6. Start in `observe`, replay historical decisions, then move through `warn` to `enforce`.

```python
from sentinelgate.client import SentinelGateClient

with SentinelGateClient("https://sentinelgate.internal", agent_token) as gate:
    context = {"body": retrieved_text}
    attestation = gate.attest_structured(
        "web:https://example.test/page",
        context,
        trust="untrusted",
        trace_id=trace_id,
    )
    decision = gate.evaluate(
        user_id=user_id,
        tool_name="send_email",
        arguments={"to": recipient, "subject": subject, "body": retrieved_text},
        field_provenance={
            "/body": [{"token": attestation["token"], "source_pointer": "/body"}]
        },
        trace_id=trace_id,
    )
```

The application must treat `deny` as final and `require_approval` as non-executing. It must never
fall back to the original direct connector when SentinelGate is unavailable.

## Readiness

- `GET /health` establishes process liveness and audit-chain status.
- `GET /ready` verifies database access, audit integrity and required local configuration.
- The connector console performs live GitHub verification rather than checking only for variables.

## What remains customer work

Each design partner must define tool ownership, scopes, classifications, trusted ingestion paths,
data-retention requirements, OIDC role mapping and an outage posture. SentinelGate cannot infer
these safely from traffic. Automatic policy weakening is intentionally unsupported because traffic
and retrieved content are attacker-influenceable.

Production secrets may be mounted from the customer's existing secret manager using the
`SENTINEL_*_FILE` settings documented in `.env.example`. This removes values from `.env`, but it is
not a claim of direct AWS KMS, Azure Key Vault or Google Cloud KMS envelope-encryption support.
