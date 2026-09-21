import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sentinelgate.models import AgentPrincipal, TokenResponse


class TokenError(ValueError):
    pass


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )
    if _encode(decoded) != value:
        raise ValueError("Non-canonical base64 encoding")
    return decoded


class TokenSigner:
    """Small HMAC token issuer for the MVP.

    Production deployments should replace this with OIDC workload identity and
    asymmetric keys. Tokens deliberately include an audience and token id.
    """

    def __init__(self, key: str, issuer: str):
        if len(key) < 24:
            raise ValueError("Token signing key must be at least 24 characters")
        self.key = key.encode("utf-8")
        self.issuer = issuer

    def issue(
        self, subject: str, audience: str, ttl_seconds: int, **claims: Any
    ) -> tuple[str, datetime]:
        reserved = {"iss", "sub", "aud", "iat", "exp", "jti"}
        if reserved & claims.keys():
            raise ValueError("Custom claims cannot override reserved token claims")
        now = int(time.time())
        expires = now + ttl_seconds
        header = {"alg": "HS256", "typ": "SGT"}
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": expires,
            "jti": str(uuid4()),
            **claims,
        }
        header_part = _encode(json.dumps(header, separators=(",", ":")).encode())
        payload_part = _encode(json.dumps(payload, separators=(",", ":")).encode())
        encoded = f"{header_part}.{payload_part}"
        signature = hmac.new(self.key, encoded.encode(), hashlib.sha256).digest()
        return f"{encoded}.{_encode(signature)}", datetime.fromtimestamp(expires, UTC)

    def decode(self, token: str, audience: str) -> dict[str, Any]:
        try:
            header_part, payload_part, signature_part = token.split(".")
            signed = f"{header_part}.{payload_part}".encode()
            supplied = _decode(signature_part)
            expected = hmac.new(self.key, signed, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied, expected):
                raise TokenError("Invalid token signature")
            header = json.loads(_decode(header_part))
            payload = json.loads(_decode(payload_part))
        except TokenError:
            raise
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TokenError("Malformed token") from exc
        if header != {"alg": "HS256", "typ": "SGT"}:
            raise TokenError("Unsupported token header")
        if payload.get("iss") != self.issuer or payload.get("aud") != audience:
            raise TokenError("Invalid issuer or audience")
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(
            time.time()
        ):
            raise TokenError("Token expired")
        return payload

    def issue_agent(
        self, agent_id: str, tenant_id: str, scopes: list[str], ttl_seconds: int
    ) -> TokenResponse:
        token, expires = self.issue(
            agent_id,
            "sentinelgate-agent",
            ttl_seconds,
            tenant_id=tenant_id,
            scopes=sorted(set(scopes)),
        )
        token_id = str(self.decode(token, "sentinelgate-agent")["jti"])
        return TokenResponse(access_token=token, expires_at=expires, token_id=token_id)

    def agent_principal(self, token: str) -> AgentPrincipal:
        payload = self.decode(token, "sentinelgate-agent")
        scopes = payload.get("scopes")
        if not isinstance(scopes, list) or not all(isinstance(v, str) for v in scopes):
            raise TokenError("Invalid scopes")
        return AgentPrincipal(
            agent_id=str(payload["sub"]),
            tenant_id=str(payload["tenant_id"]),
            scopes=frozenset(scopes),
            token_id=str(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
        )
