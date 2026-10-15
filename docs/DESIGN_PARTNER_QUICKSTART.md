# Design-partner quickstart

This path is for disposable or non-production data. It should take an unfamiliar Python developer
about ten minutes after Python 3.11+ is installed. It does not make a deployment production-ready.

## 1. Install and verify

On Windows PowerShell, from the extracted repository:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
.\.venv\Scripts\Activate.ps1
sentinelgate serve --reload
```

On macOS/Linux:

```bash
sh scripts/install.sh
. .venv/bin/activate
sentinelgate serve --reload
```

In a second terminal:

```bash
sentinelgate doctor --url http://127.0.0.1:8000
```

Open `http://127.0.0.1:8000/console/onboarding` and use the raw value of
`SENTINEL_ADMIN_TOKEN` from `.env` to connect. Do not prefix it with `Bearer` in the browser.

## 2. Protect the first agent

1. Issue a `research-agent` token with only the displayed example scopes.
2. Run the safe call and confirm `allow`.
3. Run the hostile call and confirm `deny`.
4. Paste the agent's OpenAI or MCP tool definitions into **Compile an integration**.
5. Generate a starter policy. Review every tool; the draft is not active.
6. Generate the snippet for Python, OpenAI Agents SDK, LangGraph, or MCP.
7. Replace one direct tool-dispatch path in a disposable agent.
8. Confirm the call appears in Gate, Data flows, and Audit.

## 3. PostgreSQL evaluation

After `sentinelgate init`, one command starts PostgreSQL and the gateway:

```bash
docker compose up --build
```

Include the durable notification worker with:

```bash
docker compose --profile notifications up --build
```

The control plane listens only on `127.0.0.1:8000` by default. The marketing process is separate
on port 8080. Do not expose either directly to the Internet without HTTPS, OIDC, reviewed tenant
boundaries, backups, monitoring, and a deployment-specific threat review.

## 4. Framework notes

Install the framework you actually use; SentinelGate does not force these dependencies into the
core installation:

```bash
pip install openai-agents
# or
pip install langgraph langchain-core
```

The local function adapters evaluate inputs before invoking the function. They cannot undo a side
effect or guarantee output mediation. Use the gateway executor and governed connectors for the
strongest boundary.

## 5. Adoption completion evidence

An evaluation is complete only when the developer can show:

- one allowed real call;
- one denied or approval-held call;
- a trace containing provenance and a stable task identifier;
- no direct fallback connector credential in the agent;
- the exact installation time and every point where help was needed.

