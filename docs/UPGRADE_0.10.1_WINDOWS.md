# Upgrade from v0.10 to v0.10.1 on Windows

Stop Uvicorn and the worker before replacing files. Commit the current repository and copy `.env` outside it as a temporary backup.

```powershell
cd C:\Users\tuanv\Durham\East\SG\sentinelgate\sentinelgate1
git status
Copy-Item .env ..\sentinelgate-v0.10.env.backup
```

Extract the v0.10.1 archive beside the repository. Copy its contents over the repository while preserving `.git` and `.env`. Do not copy an old virtual environment or database.

Recreate the environment:

```powershell
if (Test-Path .venv) { Remove-Item .venv -Recurse -Force }
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -c "import sentinelgate, inspect; print(sentinelgate.__version__); print(inspect.getfile(sentinelgate))"
pytest
```

The version command must print `0.10.1` and a path inside the active repository.

For the existing local SQLite path:

```powershell
uvicorn sentinelgate.api:app --reload
```

For the PostgreSQL evaluation path:

```powershell
$env:POSTGRES_PASSWORD = "your-existing-compose-postgres-password"
docker compose --profile notifications up --build
```

Open:

- `http://127.0.0.1:8000/learn`
- `http://127.0.0.1:8000/console/onboarding`
- `http://127.0.0.1:8000/health`

After validation, inspect `git status`, ensure `.env`, private keys, `.venv` and databases are absent, then commit the upgrade.
