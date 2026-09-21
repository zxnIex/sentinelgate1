"""Federated administrator authentication through an existing OIDC provider."""

from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient


class AdminIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdminIdentity:
    subject: str
    email: str | None
    roles: frozenset[str]


class OIDCAdminVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        role_claim: str = "roles",
    ):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.role_claim = role_claim
        self.keys = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def verify(self, token: str) -> AdminIdentity:
        try:
            key = self.keys.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "ES256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            raise AdminIdentityError("Invalid federated administrator token") from exc
        raw_roles = claims.get(self.role_claim, [])
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        if not isinstance(raw_roles, list) or not all(
            isinstance(item, str) for item in raw_roles
        ):
            raise AdminIdentityError("OIDC role claim is invalid")
        return AdminIdentity(
            subject=str(claims["sub"]),
            email=str(claims["email"]) if claims.get("email") else None,
            roles=frozenset(item.casefold() for item in raw_roles),
        )
