# Upgrade to v0.16 on Windows

v0.16 is a direct source replacement. You do not need to install v0.14 or v0.15 first.

## 1. Protect the current repository

From the Git repository root:

```powershell
git status
git switch -c upgrade/v0.16-saas-boundary
git add .
git commit -m "Checkpoint before v0.16"
```

Do not continue if `.env`, private keys, `.venv` or database files are staged.

## 2. Extract and copy

```powershell
$zip = "$env:USERPROFILE\Downloads\sentinelgate-v0.16.0.zip"
$temp = Join-Path $env:TEMP "sentinelgate-v016"
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive $zip -DestinationPath $temp -Force

robocopy "$temp\sentinelgate-v0.16.0" . /E `
  /XD .git .venv data `
  /XF .env *.db *.pem *.key
```

Robocopy exit codes 0 through 7 normally indicate success.

## 3. Keep dedicated mode for your current local installation

Add or retain:

```dotenv
SENTINEL_DEPLOYMENT_MODE=dedicated
```

Do not enable shared mode for a public deployment. Shared mode is a boundary preview and blocks
unreviewed legacy control-plane routes.

## 4. Install and verify

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]" --upgrade

python -c "import sentinelgate; print(sentinelgate.__version__); print(sentinelgate.__file__)"
pytest -q
python -m sentinelgate.redteam
```

The version must be `0.16.0`, and the path must point inside the current repository.

## 5. Run

Terminal one:

```powershell
uvicorn sentinelgate.api:app --reload
```

Terminal two, when durable notifications are configured:

```powershell
python -m sentinelgate.worker
```

Open `http://127.0.0.1:8000`. Existing `.env`, GitHub App configuration and local database are
preserved by the copy command.

## 6. Commit safely

```powershell
git check-ignore .env
git ls-files .env
git status --short
git diff --check
git add .
git status
git commit -m "Add v0.16 SaaS boundary preview"
git push -u origin upgrade/v0.16-saas-boundary
```

`git check-ignore .env` should print `.env`; `git ls-files .env` should print nothing.
