# Billing and commercial entitlements

SentinelGate v0.16 uses Stripe-hosted Checkout and the Stripe customer portal. Card and bank
details do not enter SentinelGate. The local database stores only provider identifiers,
subscription state, plan, capacity and period metadata received through signed webhooks.

## Initial catalogue

| Plan | Monthly price | Included agents | Included monthly usage | Main capability |
| --- | ---: | ---: | --- | --- |
| Gate Free | £0 | 10 | 50,000 decisions | Identity, policy, provenance, approval and MCP enforcement |
| Gate | £49 | 50 | 500,000 decisions | Higher Gate capacity and reporting |
| Watch | £199 | 50 | 1,000,000 decisions and Watch events | Deterministic timelines, findings, notifications and baselines |
| Watch+ | £499 | 100 | 3,000,000 decisions/events and 500 analyses | Selective LLM intelligence, replay and controlled response |
| Enterprise | Custom | Negotiated | Negotiated | Dedicated/self-hosted deployment, OIDC/RBAC, support and isolation controls |

Additional agent capacity is initially modelled as a £3/month recurring quantity. Do not treat
these prices as validated. Interview design partners, quote several real pilots and measure
support/infrastructure cost before publishing annual commitments.

## Stripe configuration

Create four recurring GBP prices in Stripe:

1. Gate base plan: £49/month.
2. Watch base plan: £199/month.
3. Watch+ base plan: £499/month.
4. Additional agent: £3/month per unit.

Configure the customer portal for plan changes, cancellations and payment-method updates. Create a
webhook endpoint at:

```text
https://YOUR_CONTROL_PLANE/v1/billing/webhooks/stripe
```

Subscribe it to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`

Start with Stripe test mode:

```dotenv
SENTINEL_BILLING_MODE=test
SENTINEL_STRIPE_SECRET_KEY=sk_test_...
SENTINEL_STRIPE_WEBHOOK_SECRET=whsec_...
SENTINEL_STRIPE_PRICE_GATE=price_...
SENTINEL_STRIPE_PRICE_WATCH=price_...
SENTINEL_STRIPE_PRICE_WATCH_PLUS=price_...
SENTINEL_STRIPE_PRICE_EXTRA_AGENT=price_...
```

Use mounted secret files in a production deployment. Never commit Stripe keys or webhook secrets.
Only change to `live` after test Checkout, webhook replay, cancellation, failed-payment and portal
flows all pass against a disposable tenant.

## Security properties

- Plan identifiers are selected server-side; the browser never supplies a Stripe price ID.
- Checkout metadata binds the Stripe subscription to one SentinelGate tenant.
- Webhook signatures use HMAC verification and a five-minute timestamp tolerance.
- Stripe event IDs are claimed durably, making completed events idempotent.
- Entitlements are computed from a versioned server-side catalogue rather than trusting browser or
  agent claims.
- Past-due subscriptions retain their current capability for a seven-day grace period while
  raising `billing_attention`; after that they fall back to Gate Free. This avoids silently granting
  indefinite paid access while also avoiding an abrupt security-control removal.
- Cancelled and unpaid subscriptions fall back to Gate Free when billing enforcement is enabled.

## Honest limitations

- Usage limits are checked locally; v0.16 does not yet report overage meters back to Stripe.
- A small concurrent-request overshoot is possible at a monthly boundary. Do not market the quota
  as an exact financial ledger until atomic usage reservations are added.
- The control plane is suitable for dedicated/self-hosted customer deployments. Shared public SaaS
  must wait for exhaustive cross-tenant operator-authorization tests and account lifecycle work.
- VAT, invoicing, refunds, annual contracts and sales-assisted Enterprise provisioning remain
  business processes rather than code-only features.

