"""Bounded outbound delivery for human approval notifications."""

import hashlib
import hmac
from urllib.parse import urlparse

import httpx

from sentinelgate.models import ApprovalRecord
from sentinelgate.security import canonical_json


class ApprovalNotifier:
    def __init__(
        self,
        webhook_url: str | None,
        signing_secret: str,
        console_url: str,
        client: httpx.Client | None = None,
    ):
        self.webhook_url = webhook_url.strip() if webhook_url else None
        self.signing_secret = signing_secret.encode("utf-8")
        self.console_url = console_url.rstrip("/")
        self.client = client or httpx.Client(
            timeout=5.0, follow_redirects=False, trust_env=False
        )
        if self.webhook_url:
            parsed = urlparse(self.webhook_url)
            development_local = parsed.scheme == "http" and parsed.hostname in {
                "127.0.0.1", "localhost",
            }
            if parsed.scheme != "https" and not development_local:
                raise ValueError("Approval webhook must use HTTPS or local development HTTP")
            if parsed.username or parsed.password or parsed.fragment:
                raise ValueError("Approval webhook URL contains unsupported credentials or fragment")

    @property
    def enabled(self) -> bool:
        return self.webhook_url is not None

    def notify(self, approval: ApprovalRecord, reason_codes: list[str]) -> bool:
        if not self.webhook_url:
            return False
        payload = {
            "event": "sentinelgate.approval.required",
            "approval_id": approval.id,
            "tenant_id": approval.tenant_id,
            "agent_id": approval.agent_id,
            "tool_name": approval.request.tool_name,
            "trace_id": approval.request.trace_id,
            "reason_codes": reason_codes,
            "expires_at": approval.expires_at.isoformat(),
            "review_url": f"{self.console_url}/console/approvals",
            "text": (
                f"SentinelGate approval required: {approval.request.tool_name} "
                f"for {approval.agent_id}. Review: {self.console_url}/console/approvals"
            ),
        }
        encoded = canonical_json(payload).encode("utf-8")
        signature = hmac.new(
            self.signing_secret, encoded, hashlib.sha256
        ).hexdigest()
        try:
            response = self.client.post(
                self.webhook_url,
                content=encoded,
                headers={
                    "Content-Type": "application/json",
                    "X-SentinelGate-Signature": f"sha256={signature}",
                },
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False
