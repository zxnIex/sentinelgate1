# Upgrade from SentinelGate v0.10.1 to v0.11.0 on Windows

The safest upgrade keeps the Git repository and `.env`, replaces application files, then recreates
the virtual environment. Do not commit `.env`, database files, private keys or the old `.venv`.

From the repository root on a new branch:

```powershell
git switch -c upgrade/v0.11
```

Extract the v0.11 archive beside the repository. Copy its contents over the repository while
preserving `.git` and `.env`. Then run:

```powershell
if (Test-Path .\.venv) { Remove-Item .\.venv -Recurse -Force }
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m pytest
python -m sentinelgate.redteam
python -m sentinelgate.watch_simulator --output evidence\watch-alpha-v0.11.json
python -c "import sentinelgate; print(sentinelgate.__version__, sentinelgate.__file__)"
```

The version command must print `0.11.0` and a path inside the active repository.

Compare `.env.example` with `.env` and add:

```dotenv
SENTINEL_WATCH_ENABLED=true
SENTINEL_WATCH_MONITOR_ONLY=true
```

Do not set monitor-only to false. Watch Alpha has no autonomous intervention mode. Existing SQLite
databases are migrated on startup by adding the Watch tables. Production PostgreSQL deployments
should take and verify a backup before starting the new application image.

Start the API and durable worker in separate terminals:

```powershell
uvicorn sentinelgate.api:app --reload
python -m sentinelgate.worker
```

Open `http://127.0.0.1:8000/console/watch`. Existing agent tokens remain valid, but explicit task and
progress-event ingestion requires a newly issued token containing `watch:write`. Ordinary mediated
tool calls are observed automatically and do not require that additional scope.
