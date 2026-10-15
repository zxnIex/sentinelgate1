$ErrorActionPreference = "Stop"

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher not found. Install Python 3.11 or newer first."
}

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
& .\.venv\Scripts\sentinelgate.exe init
& .\.venv\Scripts\sentinelgate.exe doctor

Write-Host "Installation verified. Start with:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  sentinelgate serve --reload"
Write-Host "Or start PostgreSQL + gateway: docker compose up --build"
