"""Public site process. It contains no control-plane routes or credentials."""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from sentinelgate.dashboard import LANDING_HTML

app = FastAPI(title="SentinelGate website", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "marketing"}


@app.get("/", response_class=HTMLResponse)
def landing() -> str:
    return LANDING_HTML
