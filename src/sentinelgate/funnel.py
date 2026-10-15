"""Privacy-minimised, explicit opt-in onboarding funnel telemetry."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

import httpx

ALLOWED_EVENTS = frozenset(
    {
        "init_started",
        "init_completed",
        "doctor_started",
        "doctor_passed",
        "doctor_failed",
        "policy_generated",
        "snippet_generated",
        "demo_started",
        "demo_completed",
    }
)


class FunnelRecorder:
    def __init__(
        self,
        root: Path,
        *,
        enabled: bool = False,
        endpoint: str | None = None,
    ) -> None:
        self.root = root
        self.enabled = enabled
        self.endpoint = endpoint

    def record(self, event: str, *, success: bool = True) -> None:
        if not self.enabled or event not in ALLOWED_EVENTS:
            return
        state = self.root / ".sentinelgate"
        state.mkdir(parents=True, exist_ok=True)
        installation_path = state / "installation-id"
        if installation_path.exists():
            installation_id = installation_path.read_text(encoding="utf-8").strip()
        else:
            installation_id = secrets.token_hex(16)
            installation_path.write_text(installation_id, encoding="utf-8")
        payload = {
            "schema_version": "1.0",
            "installation_id": installation_id,
            "event": event,
            "success": success,
            "occurred_at": datetime.now(UTC).isoformat(),
            "product_version": "0.17.0",
        }
        with (state / "onboarding-events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")
        if self.endpoint and self.endpoint.startswith("https://"):
            try:
                httpx.post(self.endpoint, json=payload, timeout=2.0, trust_env=False)
            except httpx.HTTPError:
                pass
