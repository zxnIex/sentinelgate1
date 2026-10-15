# v0.16 SaaS boundary

## What this release implements

v0.16 establishes a local account and organisation boundary around an external OIDC identity:

- OIDC supplies authentication, email and MFA policy.
- SentinelGate stores no passwords.
- An opaque browser-session token is stored only as a keyed digest; logout and account
  deactivation revoke it server-side.
- State-changing cookie requests require a separate session-bound CSRF value.
- Organisation access comes from an active local membership. A global OIDC administrator role
  does not grant access to another organisation in shared mode.
- Roles are `viewer`, `analyst`, `approver`, `administrator` and `owner`.
- Invitations are email-bound, expire, are single-use and cannot grant owner.
- Organisation creation and invitation actions have atomic account-level abuse limits.
- Terms and privacy acceptance records are versioned and store keyed metadata digests rather than
  raw IP address or user-agent values.
- Organisation deletion enters a reversible grace period. Final erasure is an offline reviewed
  operation so one web request cannot destroy a tenant.

## Fail-closed shared-mode migration

Set `SENTINEL_DEPLOYMENT_MODE=shared` only while testing the new boundary. The server permits:

- public health, documentation, pricing and authentication routes;
- account, organisation, invitation and legal-acceptance routes;
- signed Stripe webhooks and the public plan catalogue;
- agent-authenticated Gate, provenance, Watch ingestion and MCP data-plane routes.

Every older control-plane route that has not completed tenant scoping returns HTTP 503 with code
`SHARED_SAAS_ROUTE_NOT_HARDENED`. Dedicated mode preserves the existing design-partner console.
This explicit interruption is preferable to silently exposing a global list.

## What code cannot complete

Do not call the product public-SaaS-ready until all of these external gates are complete:

1. A solicitor approves terms, privacy/cookie notices, DPA and deletion/retention language.
2. An accountant or payments adviser confirms VAT, invoicing, refunds and record retention.
3. Stripe test and live webhook flows are exercised using real configured products and prices.
4. Every legacy control-plane route receives tenant-isolation tests and is moved onto the reviewed
   allowlist.
5. PostgreSQL backup, restore and managed failover drills run in the chosen hosting environment.
6. Independent penetration testing and cross-tenant authorization review complete.
7. At least one design partner runs realistic traffic, including cancellation and deletion drills.
8. On-call ownership, alerts, incident response and customer support are staffed and tested.

## Required production configuration

Shared production mode requires OIDC-only authentication, test/live billing, PostgreSQL, HTTPS,
strong distinct secrets and non-draft legal-document versions. These checks prevent obvious bad
configurations; they do not certify the deployment.

Keep the working product name private. The current name collides with an existing MCP security
project, and the suggested name `SentryGate` also has active software/commercial and trademark
uses. Select a replacement only after UK/US/EU trademark and domain review.
