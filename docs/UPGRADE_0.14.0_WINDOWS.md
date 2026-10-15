# Upgrade SentinelGate v0.11 to v0.14 on Windows

Create a branch before copying the release over the repository:

```powershell
git switch main
git pull origin main
git switch -c upgrade/v0.14-gate-watch-respond
```

Extract the v0.14 archive to a temporary directory and copy it over the repository while
preserving local state:

```powershell
$zip = "$env:USERPROFILE\Downloads\sentinelgate-v0.14.0.zip"
$temp = Join-Path $env:TEMP "sentinelgate-v014"
Expand-Archive $zip -DestinationPath $temp -Force

robocopy "$temp\sentinelgate-v0.14.0" . /E `
  /XD .git .venv data `
  /XF .env *.db *.pem *.key
```

Robocopy exit codes `0` through `7` normally indicate success. Do not replace `.env`, `.git`,
private keys, the local database or the virtual environment.

Then install and verify:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]" --upgrade
python -c "import sentinelgate; print(sentinelgate.__version__, sentinelgate.__file__)"
pytest -q
python -m sentinelgate.redteam
python -m sentinelgate.watch_evaluation --output evidence\watch-beta-v0.14-local.json
```

The version must be `0.14.0` and the import path must point inside the repository. Start the API
and worker as before. Existing Watch rows are migrated in place; new event columns default to
schema `1.0`, so v0.11 data remains readable.

Before committing, confirm `.env`, private keys, databases and local evidence are ignored:

```powershell
git check-ignore .env
git status --short
git diff --check
```
