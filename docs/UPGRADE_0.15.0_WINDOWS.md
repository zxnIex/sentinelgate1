# Upgrade SentinelGate v0.14 to v0.15 on Windows

Create a branch and preserve the current environment, database and Git metadata:

```powershell
cd C:\Users\tuanv\Durham\East\SG\sentinelgate\sentinelgate1
git switch main
git pull origin main
git switch -c upgrade/v0.15-commercial-watch-plus

$zip = "$env:USERPROFILE\Downloads\sentinelgate-v0.15.0.zip"
$temp = Join-Path $env:TEMP "sentinelgate-v015"
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive $zip -DestinationPath $temp -Force

robocopy "$temp\sentinelgate-v0.15.0" . /E `
  /XD .git .venv data `
  /XF .env *.db *.pem *.key
```

Billing and Watch Intelligence are disabled by default, so an existing v0.14 `.env` remains valid.
Install and test before enabling either subsystem:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]" --upgrade
python -c "import sentinelgate; print(sentinelgate.__version__)"
pytest -q
python -m sentinelgate.redteam
uvicorn sentinelgate.api:app --reload
```

Start `python -m sentinelgate.worker` in a second terminal. Use Stripe test mode and the settings in
`docs/BILLING.md` before enabling live billing. Do not merge until PostgreSQL CI is green.

