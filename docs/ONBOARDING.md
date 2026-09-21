# Developer onboarding

## Local evaluation

1. Install the package and copy `.env.example` to `.env`.
2. Generate four distinct random SentinelGate secrets.
3. Start `uvicorn sentinelgate.api:app --reload`.
4. Open `http://127.0.0.1:8000/console/onboarding`.
5. Sign in with the raw local admin token, without a `Bearer` prefix.
6. Review the environment checks, issue a scoped agent identity and copy its token.
7. Run the safe and hostile test calls. Confirm both appear in Overview and Audit.
8. Replace the example client URL/token with environment variables in the agent application.

## Company operator sign-in

SentinelGate does not provide public password signup. Configure an existing OIDC provider with
issuer, audience, JWKS, role mappings, authorization endpoint, token endpoint, client ID and client
secret. The browser flow uses authorization code + PKCE; the returned access token is verified by
the same issuer/audience/role logic used for API bearer authentication.

The client secret may be file-mounted through `SENTINEL_OIDC_CLIENT_SECRET_FILE`. Production also
requires an HTTPS `SENTINEL_CONSOLE_PUBLIC_URL`.

## Pilot acceptance check

A new developer should be able to:

- identify the exact tool call that SentinelGate mediates;
- issue a least-privilege agent identity;
- demonstrate one allowed and one denied call;
- see field/trace lineage for connector data;
- review and execute an approval once;
- verify connector credentials live;
- export evidence and explain its non-certification boundary;
- find database, worker and queue health without reading source code.

If this cannot be completed in under an hour with one real agent workflow, onboarding remains the
priority over adding another connector.
