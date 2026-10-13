# Ten-minute local evaluation

This path is for a disposable development environment. It is not a production deployment guide.

## Prerequisites

- Git;
- Docker Desktop with Compose;
- PowerShell 7 recommended on Windows;
- four distinct generated SentinelGate secrets;
- ports 8000 and 5432 available.

## 1. Clone and configure

```powershell
git clone YOUR_REPOSITORY_URL sentinelgate
cd .\sentinelgate
Copy-Item .env.example .env
$env:POSTGRES_PASSWORD = "generate-a-long-local-password"
```

Place distinct generated values in `.env` for the audit signing key, token signing key, data-encryption key, administrator token and approval-webhook secret. Do not commit `.env`.

## 2. Start PostgreSQL, gateway and worker

```powershell
docker compose --profile notifications up --build
```

Wait for PostgreSQL to become healthy. Open `http://127.0.0.1:8000/health` and then `/console/onboarding`.

## 3. Sign in and issue an agent identity

Paste the raw local administrator token into the control-plane sign-in dialog—do not include `Bearer`. In Onboarding, issue a token for `research-agent` with only the scopes required by the included examples.

## 4. Prove the safe path

Run the safe knowledge-search scenario from Onboarding. Confirm an `allow` decision appears in Overview and Audit.

## 5. Prove the hostile path

Run the hostile provenance scenario. Confirm the outbound action is denied and that Data flows shows its untrusted source, inherited field label, destination and reason code.

## Acceptance check

- health reports version 0.11.0;
- database backend reports PostgreSQL;
- a notification worker heartbeat appears in System health;
- one safe call is allowed;
- one hostile call is denied;
- both are present in Audit;
- `.env`, private keys and database files remain ignored by Git.

If any condition fails, do not connect a production agent. Record the exact command, response and relevant audit event first.
