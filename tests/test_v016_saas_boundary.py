from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from sentinelgate.admin_identity import AdminIdentity
from sentinelgate.api import _operator_identity, app, get_saas_identity, get_store
from sentinelgate.models import (
    LegalAcceptanceRequest,
    MembershipRole,
    OrganisationCreateRequest,
    utc_now,
)
from sentinelgate.saas import SaaSIdentityError, SaaSIdentityService
from sentinelgate.settings import Settings, get_settings


def _identity(subject: str, email: str) -> AdminIdentity:
    return AdminIdentity(subject=subject, email=email, roles=frozenset())


def _service(store) -> SaaSIdentityService:
    return SaaSIdentityService(
        store,
        "saas-test-signing-key-at-least-32-characters",
        terms_version="terms-1",
        privacy_version="privacy-1",
    )


def _accept(service: SaaSIdentityService, identity: AdminIdentity) -> None:
    service.sync_account(identity.subject, identity.email)
    service.accept_legal(
        identity,
        LegalAcceptanceRequest(terms_version="terms-1", privacy_version="privacy-1"),
        "127.0.0.1",
        "test-agent",
    )


def test_membership_is_tenant_bound_and_oidc_roles_do_not_grant_cross_tenant(store):
    service = _service(store)
    alice = _identity("alice", "alice@example.test")
    bob = _identity("bob", "bob@example.test")
    _accept(service, alice)
    _accept(service, bob)
    first = service.create_organisation(
        alice, OrganisationCreateRequest(name="First", tenant_id="first")
    )
    second = service.create_organisation(
        bob, OrganisationCreateRequest(name="Second", tenant_id="second")
    )

    bound = service.bind_tenant(alice, first.tenant_id)
    assert bound.membership_role == "owner"
    assert "administrator" in bound.roles
    with pytest.raises(SaaSIdentityError, match="No active membership"):
        service.bind_tenant(alice, second.tenant_id)

    forged_global_role = AdminIdentity(
        subject="alice",
        email="alice@example.test",
        roles=frozenset({"administrator"}),
    )
    with pytest.raises(SaaSIdentityError, match="No active membership"):
        service.require_membership(forged_global_role, second.tenant_id)


def test_invitation_is_email_bound_one_time_and_cannot_grant_owner(store):
    service = _service(store)
    owner = _identity("owner", "owner@example.test")
    invited = _identity("member", "member@example.test")
    wrong = _identity("wrong", "wrong@example.test")
    for identity in (owner, invited, wrong):
        _accept(service, identity)
    service.create_organisation(
        owner, OrganisationCreateRequest(name="Acme", tenant_id="acme")
    )

    with pytest.raises(SaaSIdentityError, match="Ownership transfer"):
        service.create_invitation(
            owner, "acme", invited.email or "", MembershipRole.OWNER, 24
        )
    issued = service.create_invitation(
        owner, "acme", invited.email or "", MembershipRole.ANALYST, 24
    )
    with pytest.raises(SaaSIdentityError, match="another email"):
        service.accept_invitation(wrong, issued.token)
    membership = service.accept_invitation(invited, issued.token)
    assert membership.role is MembershipRole.ANALYST
    with pytest.raises(SaaSIdentityError, match="invalid"):
        service.accept_invitation(invited, issued.token)


def test_browser_session_is_opaque_revocable_and_csrf_bound(store):
    service = _service(store)
    identity = _identity("operator", "operator@example.test")
    _accept(service, identity)
    service.create_organisation(
        identity, OrganisationCreateRequest(name="Runtime", tenant_id="runtime")
    )
    raw_token, created = service.create_browser_session(
        identity.subject, identity.email
    )
    assert raw_token not in str(store.path.read_bytes())
    resolved = service.resolve_browser_session(raw_token, "runtime")
    assert resolved.tenant_id == "runtime"
    assert service.verify_csrf(resolved, created.csrf_token) is True
    assert service.verify_csrf(resolved, "wrong") is False
    assert store.revoke_operator_session(created.id) is True
    with pytest.raises(SaaSIdentityError, match="invalid or expired"):
        service.resolve_browser_session(raw_token, "runtime")


def test_organisation_deletion_is_delayed_and_reversible(store):
    service = _service(store)
    owner = _identity("owner", "owner@example.test")
    _accept(service, owner)
    service.create_organisation(
        owner, OrganisationCreateRequest(name="Delete Me", tenant_id="delete-me")
    )
    execute_after = utc_now() + timedelta(days=30)
    store.schedule_tenant_deletion(
        "delete-me", owner.subject, "requested", execute_after
    )
    assert store.get_organisation("delete-me").status.value == "deletion_pending"
    assert store.get_membership("delete-me", owner.subject) is None
    assert store.cancel_tenant_deletion("delete-me") is True
    assert store.get_organisation("delete-me").status.value == "active"


def test_shared_production_rejects_draft_legal_documents(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_AUDIT_SIGNING_KEY", "a" * 48)
    monkeypatch.setenv("SENTINEL_TOKEN_SIGNING_KEY", "b" * 48)
    monkeypatch.setenv("SENTINEL_DATA_ENCRYPTION_KEY", "c" * 48)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "d" * 48)
    monkeypatch.setenv("SENTINEL_ADMIN_AUTH_MODE", "oidc")
    monkeypatch.setenv("SENTINEL_DEPLOYMENT_MODE", "shared")
    monkeypatch.setenv("SENTINEL_BILLING_MODE", "test")
    monkeypatch.setenv("SENTINEL_STRIPE_SECRET_KEY", "sk_test_example")
    monkeypatch.setenv("SENTINEL_STRIPE_WEBHOOK_SECRET", "whsec_example")
    monkeypatch.setenv("SENTINEL_STRIPE_PRICE_GATE", "price_gate")
    monkeypatch.setenv("SENTINEL_STRIPE_PRICE_WATCH", "price_watch")
    monkeypatch.setenv("SENTINEL_STRIPE_PRICE_WATCH_PLUS", "price_watch_plus")
    monkeypatch.setenv("SENTINEL_OIDC_ISSUER", "https://id.example.test")
    monkeypatch.setenv("SENTINEL_OIDC_AUDIENCE", "agent-control")
    monkeypatch.setenv("SENTINEL_OIDC_JWKS_URL", "https://id.example.test/jwks")
    monkeypatch.setenv("SENTINEL_CONSOLE_PUBLIC_URL", "https://app.example.test")
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql://control:test@db/control")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="non-draft"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_account_actions_have_atomic_abuse_limits(store):
    service = _service(store)
    owner = _identity("rate-owner", "rate-owner@example.test")
    _accept(service, owner)
    for index in range(5):
        service.create_organisation(
            owner,
            OrganisationCreateRequest(
                name=f"Allowed {index}", tenant_id=f"allowed-{index}"
            ),
        )
    with pytest.raises(SaaSIdentityError, match="Too many create organisation"):
        service.create_organisation(
            owner, OrganisationCreateRequest(name="Blocked", tenant_id="blocked")
        )


def test_shared_mode_fails_closed_for_unreviewed_legacy_routes(monkeypatch):
    monkeypatch.setenv("SENTINEL_DEPLOYMENT_MODE", "shared")
    get_settings.cache_clear()
    try:
        client = TestClient(app)
        blocked = client.get("/v1/metrics")
        assert blocked.status_code == 503
        assert blocked.json()["detail"]["code"] == "SHARED_SAAS_ROUTE_NOT_HARDENED"

        # Reviewed account and agent data-plane routes reach their own auth boundary.
        assert client.get("/v1/session").status_code == 401
        assert client.post("/v1/evaluate", json={}).status_code == 401
        assert client.get("/health").status_code == 200
    finally:
        get_settings.cache_clear()


def test_shared_reviewed_routes_reject_cross_tenant_parameters(monkeypatch, store):
    service = _service(store)
    alice = _identity("alice-api", "alice-api@example.test")
    bob = _identity("bob-api", "bob-api@example.test")
    _accept(service, alice)
    _accept(service, bob)
    service.create_organisation(
        alice, OrganisationCreateRequest(name="First API", tenant_id="first-api")
    )
    service.create_organisation(
        bob, OrganisationCreateRequest(name="Second API", tenant_id="second-api")
    )
    bound = service.bind_tenant(alice, "first-api")
    settings = Settings(deployment_mode="shared", billing_mode="disabled")
    monkeypatch.setenv("SENTINEL_DEPLOYMENT_MODE", "shared")
    get_settings.cache_clear()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_saas_identity] = lambda: service
    app.dependency_overrides[_operator_identity] = lambda: bound
    try:
        client = TestClient(app)
        assert client.get("/v1/agents?tenant_id=second-api").status_code == 403
        assert client.get("/v1/billing/entitlements/second-api").status_code == 403
        issued = client.post(
            "/v1/tokens/agents",
            json={
                "agent_id": "cross-tenant",
                "tenant_id": "second-api",
                "scopes": ["tools:search"],
                "ttl_seconds": 300,
            },
        )
        assert issued.status_code == 403
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
