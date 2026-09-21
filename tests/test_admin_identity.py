from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from sentinelgate.admin_identity import (
    AdminIdentity,
    AdminIdentityError,
    OIDCAdminVerifier,
)
from sentinelgate.api import _enforce_operator_role
from sentinelgate.settings import Settings


class Key:
    def __init__(self, key):
        self.key = key


def test_oidc_verifier_checks_signature_audience_issuer_and_roles():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OIDCAdminVerifier(
        issuer="https://id.example.test/", audience="sentinelgate",
        jwks_url="https://id.example.test/jwks", role_claim="groups",
    )
    verifier.keys.get_signing_key_from_jwt = lambda _: Key(private.public_key())
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "user-1", "email": "analyst@example.test",
            "iss": "https://id.example.test", "aud": "sentinelgate",
            "iat": now, "exp": now + timedelta(minutes=5),
            "groups": ["SentinelGate-Admin"],
        },
        private, algorithm="RS256",
    )
    identity = verifier.verify(token)
    assert identity.subject == "user-1"
    assert identity.roles == frozenset({"sentinelgate-admin"})

    wrong_audience = jwt.encode(
        {
            "sub": "user-1", "iss": "https://id.example.test", "aud": "other",
            "iat": now, "exp": now + timedelta(minutes=5), "groups": [],
        }, private, algorithm="RS256",
    )
    with pytest.raises(AdminIdentityError):
        verifier.verify(wrong_audience)


def test_operator_roles_are_least_privilege():
    settings = Settings(_env_file=None)
    viewer = AdminIdentity("viewer", None, frozenset({"sentinelgate-viewer"}))
    approver = AdminIdentity("approver", None, frozenset({"sentinelgate-approver"}))
    assert _enforce_operator_role(viewer, settings, "viewer") == viewer
    assert _enforce_operator_role(approver, settings, "approver") == approver
    with pytest.raises(Exception) as denied:
        _enforce_operator_role(viewer, settings, "approver")
    assert getattr(denied.value, "status_code", None) == 403
