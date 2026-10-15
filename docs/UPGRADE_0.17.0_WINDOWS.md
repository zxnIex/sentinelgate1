# Upgrade to v0.17 on Windows

v0.17 is a direct source replacement; intermediate versions are not required. These commands
preserve `.git`, `.env`, `.venv`, local databases, and private keys.

From the repository root:

```powershell
git status
git switch -c upgrade/v0.17-adoption
git add .
git commit -m "Checkpoint before v0.17"
```

Extract the downloaded archive to a temporary directory:

```powershell
$zip = "$env:USERPROFILE\Downloads\sentinelgate-v0.17.0.zip"
$temp = Join-Path $env:TEMP "sentinelgate-v017"
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive $zip -DestinationPath $temp -Force
```

Copy the release over the current repository:

```powershell
robocopy "$temp\sentinelgate-v0.17.0" . /E `
  /XD .git .venv data .sentinelgate `
  /XF .env *.db *.pem *.key
```

Robocopy exit codes 0–7 normally indicate success. Do not delete or recreate `.env`. Add this
optional display-only setting if desired:

```text
SENTINEL_PRODUCT_NAME=Your Cleared Product Name
```

Install and verify:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]" --upgrade
python -c "import sentinelgate; print(sentinelgate.__version__); print(sentinelgate.__file__)"
sentinelgate doctor
pytest -q
python -m sentinelgate.redteam
```

The version must be `0.17.0`, and the import path must point inside this repository. Start with:

```powershell
sentinelgate serve --reload
```

Before committing:

```powershell
git check-ignore .env
git ls-files .env
git status --short
git diff --check
```

The first command must print `.env`; the second must print nothing. Review all staged files before
you commit and push the upgrade branch.
