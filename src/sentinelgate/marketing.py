"""Public site process. It contains no control-plane routes or credentials."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from sentinelgate.dashboard import LANDING_HTML

app = FastAPI(title="SentinelGate website", docs_url=None, redoc_url=None, openapi_url=None)
app.mount(
    "/assets",
    StaticFiles(directory=Path(__file__).with_name("static"), check_dir=True),
    name="assets",
)


@app.middleware("http")
async def public_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; script-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "marketing"}


@app.get("/", response_class=HTMLResponse)
def landing() -> str:
    return LANDING_HTML
