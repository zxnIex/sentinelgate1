import base64
import binascii
import csv
import hashlib
import hmac
import io
import json
import secrets
import statistics
import time
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from sentinelgate.admin_identity import (
    AdminIdentity,
    AdminIdentityError,
    OIDCAdminVerifier,
)
from sentinelgate.billing import (
    BillingError,
    BillingWebhookProcessor,
    StripeBillingClient,
    StripeWebhookVerifier,
)
from sentinelgate.commercial import PLAN_CATALOGUE, EntitlementError, EntitlementService
from sentinelgate.dashboard import LANDING_HTML, LEARN_HTML, branded_page, console_page
from sentinelgate.executor import ToolExecutionError, demo_registry
from sentinelgate.github_connector import (
    GitHubAppClient,
    GitHubConnector,
    register_github_tools,
)
from sentinelgate.identity import TokenError, TokenSigner
from sentinelgate.mcp import handle_mcp
from sentinelgate.mcp_security import inspect_manifest
from sentinelgate.models import (
    ActivityEvent,
    AgentPrincipal,
    AgentRecord,
    ApprovalAction,
    ApprovalRecord,
    BillingCheckoutRequest,
    BillingPortalRequest,
    BillingSessionResponse,
    ContainmentRecord,
    ContainmentRequest,
    DeclassificationRequest,
    DeletionRequest,
    EntitlementSnapshot,
    ExecutionResult,
    FlightRecorder,
    Incident,
    IncidentAction,
    InterventionActionRequest,
    InterventionPlan,
    InvitationAcceptRequest,
    InvitationCreateRequest,
    InvitationTokenResponse,
    IssueAgentTokenRequest,
    LegalAcceptanceRequest,
    LineageRecord,
    MCPManifestInspectionRequest,
    MCPManifestInspectionResult,
    MembershipRole,
    OnboardingPolicyRequest,
    OnboardingSnippetRequest,
    Organisation,
    OrganisationCreateRequest,
    OTelGenAIIngestRequest,
    OTelGenAIIngestResult,
    PolicyDecision,
    PolicyReplayRequest,
    PolicyReplayResult,
    ProductPlan,
    ProvenanceAttestation,
    ProvenanceAttestRequest,
    ReleaseAgentRequest,
    ResponsePolicy,
    ResponsePolicyRequest,
    SessionRevocationRequest,
    SimulationRequest,
    StructuredProvenanceAttestRequest,
    StructuredProvenanceDeriveRequest,
    TaskRecoveryRequest,
    TenantMembership,
    TokenResponse,
    ToolCallRequest,
    TraceSummary,
    WatchEventRecord,
    WatchEventRequest,
    WatchEventType,
    WatchFinding,
    WatchFindingAction,
    WatchIntelligenceRequest,
    WatchIntelligenceResult,
    WatchProgress,
    WatchReplayRequest,
    WatchReplayResult,
    WatchSummary,
    WatchTaskCreateRequest,
    WatchTaskRecord,
    utc_now,
)
from sentinelgate.onboarding import (
    FRAMEWORKS,
    OnboardingError,
    discover_tools,
    generate_starter_policy,
    integration_snippet,
)
from sentinelgate.policy import PolicyConfigurationError, PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.reporting import security_evidence_report
from sentinelgate.respond import RespondError, RespondService
from sentinelgate.saas import SaaSIdentityError, SaaSIdentityService
from sentinelgate.service import GatewayService
from sentinelgate.settings import Settings, get_settings
from sentinelgate.storage import StorageIntegrityError, Store
from sentinelgate.telemetry import runtime_telemetry
from sentinelgate.upstream_mcp import (
    UpstreamMCPError,
    UpstreamMCPManager,
    handle_upstream_mcp,
)
from sentinelgate.watch import WatchService, WatchTaskNotFound
from sentinelgate.watch_intelligence import (
    WatchIntelligenceError,
    WatchIntelligenceService,
)

app = FastAPI(
    title="AI Agent Security Control Plane",
    version="0.17.0",
    description="Identity-aware, fail-closed security gateway for AI-agent tool calls.",
)
app.mount(
    "/assets",
    StaticFiles(directory=Path(__file__).with_name("static"), check_dir=True),
    name="assets",
)


_SHARED_SAFE_EXACT = {
    "/",
    "/learn",
    "/pricing",
    "/health",
    "/ready",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/v1/auth/config",
    "/v1/session",
    "/v1/invitations/accept",
    "/v1/billing/plans",
    "/v1/billing/checkout",
    "/v1/billing/portal",
    "/v1/billing/webhooks/stripe",
    "/v1/setup/status",
    "/v1/onboarding/frameworks",
    "/v1/onboarding/policy-draft",
    "/v1/onboarding/snippet",
    "/v1/tokens/agents",
    "/v1/agents",
    "/mcp",
    "/v1/evaluate",
    "/v1/execute",
    "/v1/provenance/attest",
    "/v1/provenance/attest-structured",
    "/v1/provenance/derive-structured",
    "/v1/watch/tasks",
    "/v1/watch/events",
    "/v1/watch/otel/v1/spans",
}
_SHARED_SAFE_PREFIXES = (
    "/assets/",
    "/auth/",
    "/console",
    "/v1/account/",
    "/v1/organisations",
    "/v1/agents/",
    "/v1/billing/entitlements/",
    "/mcp/upstream/",
)


def _shared_route_reviewed(path: str) -> bool:
    return path in _SHARED_SAFE_EXACT or path.startswith(_SHARED_SAFE_PREFIXES)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    started = time.perf_counter()
    status = 500
    try:
        if get_settings().deployment_mode == "shared" and not _shared_route_reviewed(
            request.url.path
        ):
            response = JSONResponse(
                status_code=503,
                content={
                    "detail": {
                        "code": "SHARED_SAAS_ROUTE_NOT_HARDENED",
                        "message": (
                            "This legacy control-plane route is disabled in shared "
                            "mode until its tenant boundary has been reviewed."
                        ),
                    }
                },
            )
        else:
            response = await call_next(request)
        status = response.status_code
    finally:
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        runtime_telemetry.observe(
            request.method, route_path, status, time.perf_counter() - started
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path in {"/", "/learn", "/pricing"} or request.url.path.startswith(
        "/console"
    ):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'"
        )
    return response


admin_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="AdminBearer",
    description=(
        "OIDC access token in deployments, or raw SENTINEL_ADMIN_TOKEN in development. "
        "Swagger adds the Bearer prefix."
    ),
)
agent_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="AgentBearer",
    description="Raw scoped token issued by POST /v1/tokens/agents.",
)


@lru_cache
def get_store() -> Store:
    settings = get_settings()
    return Store(
        settings.database_url or settings.database_path,
        settings.audit_signing_key,
        settings.data_encryption_key,
        pool_min_size=settings.database_pool_min_size,
        pool_max_size=settings.database_pool_max_size,
    )


@lru_cache
def get_signer() -> TokenSigner:
    settings = get_settings()
    return TokenSigner(settings.token_signing_key, settings.issuer)


@lru_cache
def get_provenance() -> ProvenanceService:
    return ProvenanceService(get_signer())


@lru_cache
def get_entitlements() -> EntitlementService:
    return EntitlementService(
        get_store(), enforcement_enabled=get_settings().billing_mode != "disabled"
    )


@lru_cache
def get_saas_identity() -> SaaSIdentityService:
    settings = get_settings()
    return SaaSIdentityService(
        get_store(),
        settings.token_signing_key,
        terms_version=settings.terms_version,
        privacy_version=settings.privacy_version,
        session_hours=settings.operator_session_hours,
    )


@lru_cache
def get_watch_service() -> WatchService:
    settings = get_settings()
    return WatchService(
        get_store(),
        enabled=settings.watch_enabled,
        monitor_only=settings.watch_monitor_only,
        durable_notifications=bool(settings.approval_webhook_url),
        notification_max_attempts=settings.worker_max_attempts,
        entitlements=get_entitlements(),
        auto_response_enabled=settings.watch_auto_response_enabled,
    )


@lru_cache
def get_watch_intelligence() -> WatchIntelligenceService:
    settings = get_settings()
    return WatchIntelligenceService(
        get_store(),
        api_key=settings.openai_api_key,
        model=settings.watch_intelligence_model or settings.openai_model,
        enabled=settings.watch_intelligence_enabled,
        allow_description=settings.watch_intelligence_allow_description,
    )


@lru_cache
def get_billing_client() -> StripeBillingClient:
    settings = get_settings()
    if settings.billing_mode == "disabled" or not settings.stripe_secret_key:
        raise BillingError("Stripe billing is disabled")
    return StripeBillingClient(
        settings.stripe_secret_key,
        settings.console_public_url,
        {
            ProductPlan.GATE: settings.stripe_price_gate or "",
            ProductPlan.WATCH: settings.stripe_price_watch or "",
            ProductPlan.WATCH_PLUS: settings.stripe_price_watch_plus or "",
        },
        settings.stripe_price_extra_agent,
    )


@lru_cache
def get_respond_service() -> RespondService:
    return RespondService(get_store(), get_watch_service())


@lru_cache
def get_service() -> GatewayService:
    settings = get_settings()
    registry = demo_registry(settings.knowledge_path)
    allowed_repositories = {
        item.strip()
        for item in settings.github_allowed_repositories.split(",")
        if item.strip()
    }
    register_github_tools(
        registry,
        GitHubConnector(
            GitHubAppClient(
                settings.github_app_id,
                settings.github_installation_id,
                settings.github_private_key_path,
                allowed_repositories,
            )
        ),
    )
    return GatewayService(
        PolicyEngine(settings.policy_path),
        get_store(),
        get_provenance(),
        registry,
        settings.enforcement_mode,
        durable_notifications=bool(settings.approval_webhook_url),
        notification_max_attempts=settings.worker_max_attempts,
        watch_service=get_watch_service(),
    )


@lru_cache
def get_upstream_mcp() -> UpstreamMCPManager:
    settings = get_settings()
    return UpstreamMCPManager(settings.mcp_upstreams_path, get_store())


@lru_cache
def get_admin_verifier() -> OIDCAdminVerifier | None:
    settings = get_settings()
    if settings.admin_auth_mode not in {"oidc", "hybrid"}:
        return None
    if not all((settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url)):
        return None
    return OIDCAdminVerifier(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=settings.oidc_jwks_url,
        role_claim=settings.oidc_role_claim,
    )


def _operator_identity(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(admin_bearer),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> AdminIdentity:
    selected_tenant = request.headers.get("X-Sentinel-Tenant")
    if credentials is not None and credentials.scheme.casefold() == "bearer":
        token = credentials.credentials
        if settings.admin_auth_mode in {"shared", "hybrid"} and hmac.compare_digest(
            token, settings.admin_token
        ):
            return AdminIdentity(
                subject="shared-development-administrator",
                email=None,
                roles=frozenset({"administrator"}),
                tenant_id=selected_tenant,
            )
        verifier = get_admin_verifier()
        if verifier is None:
            raise HTTPException(status_code=401, detail="Invalid administrator token")
        try:
            identity = verifier.verify(token)
            if settings.deployment_mode == "shared":
                identity = saas.bind_tenant(identity, selected_tenant)
            return identity
        except (AdminIdentityError, SaaSIdentityError) as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    session_token = request.cookies.get("agent_control_session")
    if not session_token:
        raise HTTPException(status_code=401, detail="Operator authentication required")
    try:
        identity = saas.resolve_browser_session(session_token, selected_tenant)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf_header = request.headers.get("X-CSRF-Token", "")
            csrf_cookie = request.cookies.get("agent_control_csrf", "")
            if not csrf_header or not hmac.compare_digest(csrf_header, csrf_cookie):
                raise SaaSIdentityError("CSRF token is missing or does not match")
            if not saas.verify_csrf(identity, csrf_header):
                raise SaaSIdentityError("CSRF token is invalid")
        return identity
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _browser_oidc_configured(settings: Settings) -> bool:
    return bool(
        settings.oidc_authorization_endpoint
        and settings.oidc_token_endpoint
        and settings.oidc_client_id
        and settings.oidc_client_secret
        and settings.oidc_issuer
        and settings.oidc_audience
        and settings.oidc_jwks_url
    )


def _encode_login_state(payload: dict[str, object], signing_key: str) -> str:
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(
        signing_key.encode(), encoded.encode(), hashlib.sha256
    ).hexdigest()
    return f"{encoded}.{signature}"


def _decode_login_state(value: str, signing_key: str) -> dict[str, object]:
    try:
        encoded, signature = value.split(".", 1)
        expected = hmac.new(
            signing_key.encode(), encoded.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if not isinstance(payload, dict) or int(payload["expires_at"]) < int(
            time.time()
        ):
            raise ValueError("expired")
        return payload
    except (
        binascii.Error,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(
            status_code=400, detail="OIDC login state is invalid"
        ) from exc


def _allowed_roles(settings: Settings, minimum: str) -> set[str]:
    hierarchy = {
        "viewer": [settings.oidc_viewer_roles],
        "analyst": [settings.oidc_viewer_roles, settings.oidc_analyst_roles],
        "approver": [settings.oidc_viewer_roles, settings.oidc_approver_roles],
        "administrator": [settings.oidc_admin_roles],
    }
    if minimum == "viewer":
        values = [
            settings.oidc_viewer_roles,
            settings.oidc_analyst_roles,
            settings.oidc_approver_roles,
            settings.oidc_admin_roles,
        ]
    elif minimum == "analyst":
        values = [settings.oidc_analyst_roles, settings.oidc_admin_roles]
    elif minimum == "approver":
        values = [settings.oidc_approver_roles, settings.oidc_admin_roles]
    else:
        values = hierarchy["administrator"]
    return {
        role.strip().casefold()
        for value in values
        for role in value.split(",")
        if role.strip()
    }


def _enforce_operator_role(
    identity: AdminIdentity, settings: Settings, minimum: str
) -> AdminIdentity:
    if "administrator" in identity.roles:
        return identity
    if not identity.roles.intersection(_allowed_roles(settings, minimum)):
        raise HTTPException(status_code=403, detail=f"{minimum.title()} role required")
    return identity


def require_admin(
    identity: AdminIdentity = Depends(_operator_identity),
    settings: Settings = Depends(get_settings),
) -> AdminIdentity:
    return _enforce_operator_role(identity, settings, "administrator")


def require_approver(
    identity: AdminIdentity = Depends(_operator_identity),
    settings: Settings = Depends(get_settings),
) -> AdminIdentity:
    return _enforce_operator_role(identity, settings, "approver")


def require_analyst(
    identity: AdminIdentity = Depends(_operator_identity),
    settings: Settings = Depends(get_settings),
) -> AdminIdentity:
    return _enforce_operator_role(identity, settings, "analyst")


def require_viewer(
    identity: AdminIdentity = Depends(_operator_identity),
    settings: Settings = Depends(get_settings),
) -> AdminIdentity:
    return _enforce_operator_role(identity, settings, "viewer")


def require_authenticated(
    identity: AdminIdentity = Depends(_operator_identity),
) -> AdminIdentity:
    """Require an active operator account without requiring tenant membership."""
    return identity


def require_agent(
    credentials: HTTPAuthorizationCredentials | None = Depends(agent_bearer),
    signer: TokenSigner = Depends(get_signer),
    store: Store = Depends(get_store),
) -> AgentPrincipal:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        principal = signer.agent_principal(credentials.credentials)
        if not store.token_is_active(principal):
            raise TokenError("Agent token is revoked or unregistered")
        return principal
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _billing_guard(operation) -> None:
    try:
        operation()
    except EntitlementError as exc:
        raise HTTPException(
            status_code=402,
            detail={"code": exc.code, "message": str(exc), "upgrade_url": "/pricing"},
        ) from exc


def _require_tenant_access(
    identity: AdminIdentity,
    tenant_id: str,
    settings: Settings,
    saas: SaaSIdentityService,
    allowed: set[MembershipRole] | None = None,
) -> None:
    """Bind shared-mode operator actions to their selected organisation."""
    if settings.deployment_mode != "shared":
        return
    if not identity.tenant_id or not hmac.compare_digest(identity.tenant_id, tenant_id):
        raise HTTPException(
            status_code=403,
            detail="Request tenant does not match the selected organisation",
        )
    try:
        saas.require_membership(identity, tenant_id, allowed)
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/v1/auth/config")
def auth_config(settings: Settings = Depends(get_settings)) -> dict[str, object]:
    browser_sso = _browser_oidc_configured(settings)
    return {
        "mode": settings.admin_auth_mode,
        "federated_sign_in": settings.admin_auth_mode in {"oidc", "hybrid"},
        "development_token": settings.admin_auth_mode in {"shared", "hybrid"},
        "self_service_signup": settings.self_service_signup_enabled,
        "browser_sso": browser_sso,
        "login_url": "/auth/login" if browser_sso else None,
        "signup_reason": (
            "The control plane delegates credentials and MFA to OIDC while maintaining "
            "local organisation membership, roles, sessions and lifecycle state."
        ),
    }


@app.get("/auth/login")
def oidc_login(
    next_path: str = Query(default="/console", alias="next"),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if not _browser_oidc_configured(settings):
        raise HTTPException(
            status_code=404, detail="Browser OIDC sign-in is not configured"
        )
    if not next_path.startswith("/console") or next_path.startswith("//"):
        next_path = "/console"
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    redirect_uri = f"{settings.console_public_url.rstrip('/')}/auth/callback"
    payload = {
        "state": state,
        "verifier": verifier,
        "next": next_path,
        "expires_at": int(time.time()) + 600,
    }
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "audience": settings.oidc_audience,
        }
    )
    response = RedirectResponse(
        f"{settings.oidc_authorization_endpoint}?{query}", status_code=303
    )
    response.set_cookie(
        "sentinelgate_oidc_state",
        _encode_login_state(payload, settings.token_signing_key),
        max_age=600,
        httponly=True,
        secure=settings.environment.casefold() == "production",
        samesite="lax",
        path="/auth",
    )
    return response


@app.get("/auth/callback")
def oidc_callback(
    request: Request,
    code: str = Query(min_length=8, max_length=4096),
    state: str = Query(min_length=8, max_length=512),
    settings: Settings = Depends(get_settings),
    store: Store = Depends(get_store),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> RedirectResponse:
    if not _browser_oidc_configured(settings):
        raise HTTPException(
            status_code=404, detail="Browser OIDC sign-in is not configured"
        )
    cookie = request.cookies.get("sentinelgate_oidc_state")
    if not cookie:
        raise HTTPException(
            status_code=400, detail="OIDC login state cookie is missing"
        )
    login_state = _decode_login_state(cookie, settings.token_signing_key)
    if not hmac.compare_digest(str(login_state["state"]), state):
        raise HTTPException(status_code=400, detail="OIDC state does not match")
    redirect_uri = f"{settings.console_public_url.rstrip('/')}/auth/callback"
    try:
        token_response = httpx.post(
            settings.oidc_token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
                "code_verifier": login_state["verifier"],
            },
            timeout=10.0,
            follow_redirects=False,
            trust_env=False,
        )
        token_response.raise_for_status()
        access_token = str(token_response.json()["access_token"])
        identity = OIDCAdminVerifier(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            jwks_url=settings.oidc_jwks_url,
            role_claim=settings.oidc_role_claim,
        ).verify(access_token)
    except (httpx.HTTPError, KeyError, ValueError, AdminIdentityError) as exc:
        raise HTTPException(
            status_code=401, detail="OIDC code exchange failed"
        ) from exc
    store.append_audit(
        "operator_oidc_login",
        {
            "subject": identity.subject,
            "email": identity.email,
            "roles": sorted(identity.roles),
        },
    )
    try:
        raw_session, browser_session = saas.create_browser_session(
            identity.subject, identity.email
        )
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    target = str(login_state.get("next", "/console"))
    response = RedirectResponse(target, status_code=303)
    secure = settings.environment.casefold() == "production"
    response.set_cookie(
        "agent_control_session",
        raw_session,
        max_age=settings.operator_session_hours * 3600,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        "agent_control_csrf",
        browser_session.csrf_token,
        max_age=settings.operator_session_hours * 3600,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.delete_cookie("sentinelgate_oidc_state", path="/auth")
    return response


@app.get("/v1/session")
def session(
    identity: AdminIdentity = Depends(require_authenticated),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    memberships = store.list_memberships(identity.subject)
    return {
        "subject": identity.subject,
        "email": identity.email,
        "roles": sorted(identity.roles),
        "selected_tenant": identity.tenant_id,
        "membership_role": identity.membership_role,
        "memberships": [item.model_dump(mode="json") for item in memberships],
        "legal_current": store.has_legal_acceptance(
            identity.subject, settings.terms_version, settings.privacy_version
        ),
        "terms_version": settings.terms_version,
        "privacy_version": settings.privacy_version,
    }


@app.post("/v1/account/legal-acceptance", status_code=204)
def accept_legal_terms(
    payload: LegalAcceptanceRequest,
    request: Request,
    identity: AdminIdentity = Depends(require_authenticated),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> None:
    try:
        saas.accept_legal(
            identity,
            payload,
            request.client.host if request.client else None,
            request.headers.get("User-Agent"),
        )
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/account/logout", status_code=204)
def logout_operator(
    response: Response,
    identity: AdminIdentity = Depends(require_authenticated),
    store: Store = Depends(get_store),
) -> None:
    if identity.session_id:
        store.revoke_operator_session(identity.session_id)
    response.delete_cookie("agent_control_session", path="/")
    response.delete_cookie("agent_control_csrf", path="/")


@app.delete("/v1/account", status_code=204)
def delete_operator_account(
    identity: AdminIdentity = Depends(require_authenticated),
    store: Store = Depends(get_store),
) -> None:
    if not store.deactivate_operator_account(identity.subject):
        raise HTTPException(
            status_code=409,
            detail="Transfer or delete organisations you own before deleting the account",
        )


@app.get("/v1/organisations", response_model=list[Organisation])
def organisations_for_operator(
    identity: AdminIdentity = Depends(require_authenticated),
    store: Store = Depends(get_store),
) -> list[Organisation]:
    result = []
    for membership in store.list_memberships(identity.subject):
        organisation = store.get_organisation(membership.tenant_id)
        if organisation is not None:
            result.append(organisation)
    return result


@app.post("/v1/organisations", response_model=Organisation)
def create_organisation(
    payload: OrganisationCreateRequest,
    identity: AdminIdentity = Depends(require_authenticated),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> Organisation:
    if (
        settings.deployment_mode == "shared"
        and not settings.self_service_signup_enabled
    ):
        raise HTTPException(status_code=403, detail="Self-service signup is disabled")
    try:
        return saas.create_organisation(identity, payload)
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post(
    "/v1/organisations/{tenant_id}/invitations",
    response_model=InvitationTokenResponse,
)
def invite_operator(
    tenant_id: str,
    payload: InvitationCreateRequest,
    identity: AdminIdentity = Depends(require_authenticated),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> InvitationTokenResponse:
    try:
        return saas.create_invitation(
            identity,
            tenant_id,
            payload.email,
            payload.role,
            payload.expires_in_hours,
        )
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/v1/invitations/accept", response_model=TenantMembership)
def accept_operator_invitation(
    payload: InvitationAcceptRequest,
    identity: AdminIdentity = Depends(require_authenticated),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> TenantMembership:
    try:
        return saas.accept_invitation(identity, payload.token)
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/organisations/{tenant_id}/export")
def export_organisation_inventory(
    tenant_id: str,
    identity: AdminIdentity = Depends(require_authenticated),
    saas: SaaSIdentityService = Depends(get_saas_identity),
    store: Store = Depends(get_store),
) -> dict[str, object]:
    try:
        saas.require_membership(
            identity,
            tenant_id,
            {MembershipRole.OWNER, MembershipRole.ADMINISTRATOR},
        )
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return store.tenant_export_summary(tenant_id)


@app.post("/v1/organisations/{tenant_id}/deletion-request", status_code=202)
def request_organisation_deletion(
    tenant_id: str,
    payload: DeletionRequest,
    identity: AdminIdentity = Depends(require_authenticated),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
    store: Store = Depends(get_store),
) -> dict[str, object]:
    try:
        saas.require_membership(
            identity,
            tenant_id,
            {MembershipRole.OWNER},
        )
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if payload.confirmation != tenant_id:
        raise HTTPException(status_code=422, detail="Confirmation must equal tenant ID")
    execute_after = utc_now() + timedelta(days=settings.tenant_deletion_grace_days)
    store.schedule_tenant_deletion(
        tenant_id, identity.subject, payload.reason, execute_after
    )
    return {
        "status": "deletion_pending",
        "execute_after": execute_after.isoformat(),
        "automatic_deletion": False,
        "note": "A reviewed deletion worker/runbook must execute the request.",
    }


@app.post("/v1/organisations/{tenant_id}/deletion-request/cancel", status_code=204)
def cancel_organisation_deletion(
    tenant_id: str,
    identity: AdminIdentity = Depends(require_authenticated),
    saas: SaaSIdentityService = Depends(get_saas_identity),
    store: Store = Depends(get_store),
) -> None:
    try:
        saas.require_membership(
            identity,
            tenant_id,
            {MembershipRole.OWNER},
            allow_deletion_pending=True,
        )
    except SaaSIdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not store.cancel_tenant_deletion(tenant_id):
        raise HTTPException(status_code=409, detail="No pending deletion request")


@app.get("/health")
def health(store: Store = Depends(get_store)) -> dict[str, object]:
    return {
        "status": "ok",
        "product_name": get_settings().product_name,
        "version": app.version,
        "enforcement_mode": get_settings().enforcement_mode.value,
        "audit_chain_valid": store.verify_audit_chain(),
    }


@app.get("/ready")
def ready(store: Store = Depends(get_store)) -> dict[str, object]:
    settings = get_settings()
    checks = {
        "database": store.backend,
        "audit_chain_valid": store.verify_audit_chain(),
        "policy_file": settings.policy_path.is_file(),
        "mcp_configuration": settings.mcp_upstreams_path.is_file(),
    }
    if not checks["audit_chain_valid"] or not checks["policy_file"]:
        raise HTTPException(
            status_code=503, detail={"status": "not_ready", "checks": checks}
        )
    return {"status": "ready", "checks": checks}


@app.get("/v1/setup/status", dependencies=[Depends(require_viewer)])
def setup_status(
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    workers = store.worker_status()
    webhook_enabled = bool(settings.approval_webhook_url)
    audit_valid = store.verify_audit_chain()
    checks = [
        {
            "id": "database",
            "label": "Transactional database",
            "status": "passing" if store.backend == "postgresql" else "review",
            "detail": store.backend,
            "required_for_production": True,
        },
        {
            "id": "audit",
            "label": "Audit chain",
            "status": "passing" if audit_valid else "blocked",
            "detail": "HMAC chain verified" if audit_valid else "Integrity failure",
            "required_for_production": True,
        },
        {
            "id": "policy",
            "label": "Policy loaded",
            "status": "passing" if settings.policy_path.is_file() else "blocked",
            "detail": str(settings.policy_path),
            "required_for_production": True,
        },
        {
            "id": "identity",
            "label": "Operator identity",
            "status": "passing"
            if settings.admin_auth_mode in {"oidc", "hybrid"}
            else "review",
            "detail": settings.admin_auth_mode,
            "required_for_production": True,
        },
        {
            "id": "notifications",
            "label": "Approval delivery",
            "status": (
                "passing"
                if webhook_enabled and any(w["status"] == "online" for w in workers)
                else "review"
                if webhook_enabled
                else "optional"
            ),
            "detail": (
                "durable worker online"
                if webhook_enabled and workers
                else "webhook configured; start worker"
                if webhook_enabled
                else "not configured"
            ),
            "required_for_production": False,
        },
    ]
    return {
        "version": app.version,
        "environment": settings.environment,
        "enforcement_mode": settings.enforcement_mode.value,
        "checks": checks,
        "ready_for_local_evaluation": all(
            item["status"] != "blocked" for item in checks
        ),
        "ready_for_production": (
            settings.environment.casefold() == "production"
            and all(
                item["status"] == "passing"
                for item in checks
                if item["required_for_production"]
            )
        ),
    }


@app.get("/v1/onboarding/frameworks", dependencies=[Depends(require_viewer)])
def onboarding_frameworks() -> dict[str, object]:
    return {"frameworks": list(FRAMEWORKS), "policy_activation": "manual_review"}


@app.post("/v1/onboarding/policy-draft", dependencies=[Depends(require_analyst)])
def onboarding_policy_draft(request: OnboardingPolicyRequest) -> dict[str, object]:
    try:
        tools = discover_tools(request.tools)
        return generate_starter_policy(tools, request.agent_id)
    except OnboardingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/onboarding/snippet", dependencies=[Depends(require_viewer)])
def onboarding_snippet(request: OnboardingSnippetRequest) -> dict[str, str]:
    try:
        return {
            "framework": request.framework,
            "snippet": integration_snippet(
                request.framework, tool_name=request.tool_name
            ),
        }
    except OnboardingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/mcp")
def mcp_endpoint(
    payload: dict,
    principal: AgentPrincipal = Depends(require_agent),
    service: GatewayService = Depends(get_service),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> dict:
    _billing_guard(lambda: entitlements.require_decision_capacity(principal.tenant_id))
    return handle_mcp(payload, principal, service)


@app.post("/mcp/upstream/{server_id}")
def upstream_mcp_endpoint(
    server_id: str,
    payload: dict,
    principal: AgentPrincipal = Depends(require_agent),
    service: GatewayService = Depends(get_service),
    manager: UpstreamMCPManager = Depends(get_upstream_mcp),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> dict:
    _billing_guard(lambda: entitlements.require_decision_capacity(principal.tenant_id))
    return handle_upstream_mcp(server_id, payload, principal, service, manager)


@app.post(
    "/v1/mcp/servers/{server_id}/inspect",
    response_model=MCPManifestInspectionResult,
    dependencies=[Depends(require_admin)],
)
def inspect_mcp_server(
    server_id: str,
    request: MCPManifestInspectionRequest,
    store: Store = Depends(get_store),
) -> MCPManifestInspectionResult:
    if (
        not server_id
        or len(server_id) > 128
        or not all(
            character.isalnum() or character in "_.:-" for character in server_id
        )
    ):
        raise HTTPException(status_code=422, detail="Invalid MCP server identifier")
    return inspect_manifest(server_id, request, store)


@app.get("/v1/mcp/servers", dependencies=[Depends(require_viewer)])
def mcp_servers(store: Store = Depends(get_store)) -> list[dict]:
    return store.list_mcp_tool_baselines()


@app.post("/v1/tokens/agents", response_model=TokenResponse)
def issue_agent_token(
    request: IssueAgentTokenRequest,
    signer: TokenSigner = Depends(get_signer),
    store: Store = Depends(get_store),
    entitlements: EntitlementService = Depends(get_entitlements),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
    identity: AdminIdentity = Depends(require_admin),
) -> TokenResponse:
    _require_tenant_access(
        identity,
        request.tenant_id,
        settings,
        saas,
        {MembershipRole.OWNER, MembershipRole.ADMINISTRATOR},
    )
    _billing_guard(
        lambda: entitlements.require_agent_capacity(request.tenant_id, request.agent_id)
    )
    response = signer.issue_agent(
        request.agent_id, request.tenant_id, request.scopes, request.ttl_seconds
    )
    principal = signer.agent_principal(response.access_token)
    store.register_agent_token(principal, request.owner)
    store.append_audit(
        "agent_token_issued",
        {
            "agent_id": request.agent_id,
            "tenant_id": request.tenant_id,
            "scopes": sorted(set(request.scopes)),
            "expires_at": response.expires_at.isoformat(),
        },
    )
    return response


@app.get(
    "/v1/agents",
    response_model=list[AgentRecord],
    dependencies=[Depends(require_viewer)],
)
def agents(
    tenant_id: str | None = None,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
    identity: AdminIdentity = Depends(require_viewer),
) -> list[AgentRecord]:
    if settings.deployment_mode == "shared":
        if not identity.tenant_id:
            raise HTTPException(status_code=400, detail="Select an organisation")
        if tenant_id and tenant_id != identity.tenant_id:
            raise HTTPException(status_code=403, detail="Tenant boundary mismatch")
        tenant_id = identity.tenant_id
    return store.list_agents(tenant_id)


@app.post(
    "/v1/agents/{tenant_id}/{agent_id}/revoke",
)
def revoke_agent(
    tenant_id: str,
    agent_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> dict[str, int]:
    _require_tenant_access(
        identity,
        tenant_id,
        settings,
        saas,
        {MembershipRole.OWNER, MembershipRole.ADMINISTRATOR},
    )
    count = store.revoke_agent_tokens(
        tenant_id, agent_id, action.note or "Administrative revocation"
    )
    store.append_audit(
        "agent_tokens_revoked",
        {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "reviewer": identity.email or identity.subject,
            "count": count,
        },
    )
    return {"revoked_tokens": count}


@app.post("/v1/provenance/attest", response_model=ProvenanceAttestation)
def attest_provenance(
    request: ProvenanceAttestRequest,
    principal: AgentPrincipal = Depends(require_agent),
    provenance: ProvenanceService = Depends(get_provenance),
    store: Store = Depends(get_store),
) -> ProvenanceAttestation:
    if request.trust.value == "trusted":
        required_scope = "provenance:attest:trusted"
    else:
        required_scope = "provenance:attest"
    if required_scope not in principal.scopes:
        raise HTTPException(status_code=403, detail="Missing provenance:attest scope")
    response = provenance.attest(request, principal.tenant_id)
    if request.trace_id:
        store.record_lineage(
            LineageRecord(
                id=response.lineage_id,
                tenant_id=principal.tenant_id,
                agent_id=principal.agent_id,
                trace_id=request.trace_id,
                source_type="input",
                source_id=request.source_id,
                destination="model_context",
                trust=response.trust,
                classification=response.classification,
                labels=response.labels,
                content_digest=response.content_digest,
                created_at=utc_now(),
            )
        )
    store.append_audit(
        "provenance_attested",
        {
            "agent_id": principal.agent_id,
            "tenant_id": principal.tenant_id,
            "source_id": request.source_id,
            "content_digest": response.content_digest,
            "trust": response.trust.value,
            "signals": response.signals,
        },
    )
    return response


@app.post("/v1/provenance/attest-structured", response_model=ProvenanceAttestation)
def attest_structured_provenance(
    request: StructuredProvenanceAttestRequest,
    principal: AgentPrincipal = Depends(require_agent),
    provenance: ProvenanceService = Depends(get_provenance),
    store: Store = Depends(get_store),
) -> ProvenanceAttestation:
    trusted_field_claim = any(
        str(override.get("trust", "")).casefold() == "trusted"
        for override in request.field_overrides.values()
    )
    required_scope = (
        "provenance:attest:trusted"
        if request.trust.value == "trusted" or trusted_field_claim
        else "provenance:attest"
    )
    if required_scope not in principal.scopes:
        raise HTTPException(status_code=403, detail=f"Missing {required_scope} scope")
    try:
        response = provenance.attest_structured(request, principal.tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if request.trace_id:
        store.record_lineage(
            LineageRecord(
                id=response.lineage_id,
                tenant_id=principal.tenant_id,
                agent_id=principal.agent_id,
                trace_id=request.trace_id,
                source_type="structured_input",
                source_id=request.source_id,
                destination="model_context",
                trust=response.trust,
                classification=response.classification,
                labels=response.labels,
                content_digest=response.content_digest,
                created_at=utc_now(),
                field_taint=response.field_taint,
            )
        )
    store.append_audit(
        "structured_provenance_attested",
        {
            "agent_id": principal.agent_id,
            "tenant_id": principal.tenant_id,
            "source_id": request.source_id,
            "content_digest": response.content_digest,
            "field_count": len(response.field_taint),
        },
    )
    return response


@app.post("/v1/provenance/derive-structured", response_model=ProvenanceAttestation)
def derive_structured_provenance(
    request: StructuredProvenanceDeriveRequest,
    principal: AgentPrincipal = Depends(require_agent),
    provenance: ProvenanceService = Depends(get_provenance),
    store: Store = Depends(get_store),
) -> ProvenanceAttestation:
    if "provenance:derive" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Missing provenance:derive scope")
    try:
        response = provenance.derive_structured(request, principal.tenant_id)
    except (TokenError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.record_lineage(
        LineageRecord(
            id=response.lineage_id,
            tenant_id=principal.tenant_id,
            agent_id=principal.agent_id,
            trace_id=request.trace_id,
            parent_ids=sorted(
                {
                    lineage
                    for item in response.field_taint.values()
                    for lineage in item.lineage_ids
                    if lineage != response.lineage_id
                }
            ),
            source_type=f"derived_{request.mode}",
            source_id=request.source_id,
            destination="model_context",
            trust=response.trust,
            classification=response.classification,
            labels=response.labels,
            content_digest=response.content_digest,
            created_at=utc_now(),
            field_taint=response.field_taint,
        )
    )
    store.append_audit(
        "structured_provenance_derived",
        {
            "agent_id": principal.agent_id,
            "tenant_id": principal.tenant_id,
            "source_id": request.source_id,
            "mode": request.mode,
            "field_count": len(response.field_taint),
            "content_digest": response.content_digest,
        },
    )
    return response


@app.post(
    "/v1/provenance/declassify",
    response_model=ProvenanceAttestation,
)
def declassify_provenance(
    request: DeclassificationRequest,
    provenance: ProvenanceService = Depends(get_provenance),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
    identity: AdminIdentity = Depends(require_admin),
) -> ProvenanceAttestation:
    allowed = set(settings.declassification_allowed_labels.split(",")) - {""}
    requested = {item.casefold() for item in request.remove_labels}
    if not requested.issubset(allowed):
        raise HTTPException(
            status_code=403, detail="Label is not declassifiable by policy"
        )
    try:
        response = provenance.declassify_labels(
            token=request.token,
            tenant_id=request.tenant_id,
            paths=request.paths,
            remove_labels=requested,
            reviewer=identity.email or identity.subject,
        )
    except TokenError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.append_audit(
        "field_labels_declassified",
        {
            "reviewer": identity.email or identity.subject,
            "reason": request.reason,
            "paths": request.paths,
            "removed_labels": sorted(requested),
            "lineage_id": response.lineage_id,
        },
    )
    return response


@app.post("/v1/evaluate", response_model=PolicyDecision)
def evaluate(
    call: ToolCallRequest,
    principal: AgentPrincipal = Depends(require_agent),
    service: GatewayService = Depends(get_service),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> PolicyDecision:
    _billing_guard(lambda: entitlements.require_decision_capacity(principal.tenant_id))
    if call.mcp_server_id:
        raise HTTPException(
            status_code=422,
            detail="MCP-bound tools must use /mcp/upstream/{server_id}",
        )
    return service.evaluate(call, principal)


@app.post("/v1/execute", response_model=ExecutionResult)
def execute(
    call: ToolCallRequest,
    principal: AgentPrincipal = Depends(require_agent),
    service: GatewayService = Depends(get_service),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> ExecutionResult:
    _billing_guard(lambda: entitlements.require_decision_capacity(principal.tenant_id))
    if call.mcp_server_id:
        raise HTTPException(
            status_code=422,
            detail="MCP-bound tools must use /mcp/upstream/{server_id}",
        )
    return service.execute(call, principal)


@app.get(
    "/v1/approvals",
    response_model=list[ApprovalRecord],
    dependencies=[Depends(require_viewer)],
)
def approvals(
    status: str | None = Query(
        default=None, pattern="^(pending|approved|rejected|consumed)$"
    ),
    store: Store = Depends(get_store),
) -> list[ApprovalRecord]:
    return store.list_approvals(status)


@app.post(
    "/v1/approvals/{approval_id}/approve",
    response_model=ApprovalRecord,
)
def approve(
    approval_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_approver),
) -> ApprovalRecord:
    record = store.resolve_approval(
        approval_id, "approved", identity.email or identity.subject, action.note
    )
    if not record:
        raise HTTPException(
            status_code=409, detail="Approval is missing, expired, or resolved"
        )
    store.append_audit(
        "approval_approved", {"approval_id": record.id, "reviewer": record.reviewer}
    )
    return record


@app.post(
    "/v1/approvals/{approval_id}/reject",
    response_model=ApprovalRecord,
)
def reject(
    approval_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_approver),
) -> ApprovalRecord:
    record = store.resolve_approval(
        approval_id, "rejected", identity.email or identity.subject, action.note
    )
    if not record:
        raise HTTPException(
            status_code=409, detail="Approval is missing, expired, or resolved"
        )
    store.append_audit(
        "approval_rejected", {"approval_id": record.id, "reviewer": record.reviewer}
    )
    return record


@app.post(
    "/v1/approvals/{approval_id}/execute",
    response_model=ExecutionResult,
    dependencies=[Depends(require_approver)],
)
def execute_approved(
    approval_id: str,
    service: GatewayService = Depends(get_service),
) -> ExecutionResult:
    result = service.execute_approved(approval_id)
    if not result:
        raise HTTPException(
            status_code=409, detail="Approval is invalid, expired, or already consumed"
        )
    return result


@app.post(
    "/v1/simulate",
    response_model=list[PolicyDecision],
    dependencies=[Depends(require_analyst)],
)
def simulate(
    request: SimulationRequest,
    service: GatewayService = Depends(get_service),
) -> list[PolicyDecision]:
    return service.simulate(request)


@app.post(
    "/v1/policy/replay",
    response_model=PolicyReplayResult,
    dependencies=[Depends(require_analyst)],
)
def replay_policy(
    request: PolicyReplayRequest,
    service: GatewayService = Depends(get_service),
) -> PolicyReplayResult:
    try:
        return service.replay_policy(request)
    except (PolicyConfigurationError, StorageIntegrityError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/policy", dependencies=[Depends(require_viewer)])
def current_policy(service: GatewayService = Depends(get_service)) -> dict:
    return service.policy.as_mapping()


@app.get("/v1/gate/least-privilege", dependencies=[Depends(require_analyst)])
def least_privilege_recommendations(
    minimum_observations: int = Query(default=10, ge=1, le=10_000),
    store: Store = Depends(get_store),
    service: GatewayService = Depends(get_service),
) -> dict[str, object]:
    """Recommend scope review from observed mediated usage; never revoke automatically."""
    agents = store.list_agents()
    activities = store.list_activity(limit=10_000)
    tools = service.policy.as_mapping().get("tools", {})
    results: list[dict[str, object]] = []
    for agent in agents:
        observed = [
            item
            for item in activities
            if item.tenant_id == agent.tenant_id and item.agent_id == agent.agent_id
        ]
        used_tools = sorted({item.tool_name for item in observed})
        used_scopes = {
            scope
            for name in used_tools
            for scope in tools.get(name, {}).get("required_scopes", [])
        }
        protected_scopes = {
            scope
            for scope in agent.scopes
            if scope.startswith(("watch:", "provenance:"))
        }
        unused = sorted(set(agent.scopes) - used_scopes - protected_scopes)
        sufficient = len(observed) >= minimum_observations
        results.append(
            {
                "tenant_id": agent.tenant_id,
                "agent_id": agent.agent_id,
                "observations": len(observed),
                "used_tools": used_tools,
                "current_scopes": agent.scopes,
                "candidate_unused_scopes": unused if sufficient else [],
                "status": "review"
                if sufficient and unused
                else "insufficient_data"
                if not sufficient
                else "aligned",
                "automatic_revocation": False,
            }
        )
    return {
        "minimum_observations": minimum_observations,
        "claim_boundary": (
            "Recommendations reflect mediated historical usage only. Seasonal, emergency "
            "or bypass traffic may be absent; no scope is revoked automatically."
        ),
        "agents": results,
    }


@app.get("/v1/connectors", dependencies=[Depends(require_viewer)])
def connectors(
    settings: Settings = Depends(get_settings),
    manager: UpstreamMCPManager = Depends(get_upstream_mcp),
) -> list[dict[str, object]]:
    github_values_present = bool(
        settings.github_app_id
        and settings.github_installation_id
        and settings.github_private_key_path
        and settings.github_allowed_repositories.strip()
    )
    github_configured = bool(
        github_values_present and settings.github_private_key_path.is_file()
    )
    github_status = (
        "configured"
        if github_configured
        else "invalid_private_key"
        if github_values_present
        else "not_configured"
    )
    try:
        mcp_servers = manager.server_ids()
        mcp_status = "configured" if mcp_servers else "not_configured"
    except UpstreamMCPError:
        mcp_servers = []
        mcp_status = "invalid_configuration"
    return [
        {
            "name": "knowledge",
            "status": "configured"
            if settings.knowledge_path.is_dir()
            else "unavailable",
            "mode": "read_only",
        },
        {
            "name": "github_app",
            "status": github_status,
            "mode": "read_write_with_approval",
            "repository_allowlist": sorted(
                item.strip()
                for item in settings.github_allowed_repositories.split(",")
                if item.strip()
            ),
        },
        {
            "name": "mcp_upstreams",
            "status": mcp_status,
            "mode": "inline_fail_closed",
            "servers": mcp_servers,
        },
    ]


@app.post(
    "/v1/connectors/github/verify",
    dependencies=[Depends(require_admin)],
)
def verify_github_connector(
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    repositories = {
        item.strip()
        for item in settings.github_allowed_repositories.split(",")
        if item.strip()
    }
    client = GitHubAppClient(
        settings.github_app_id,
        settings.github_installation_id,
        settings.github_private_key_path,
        repositories,
    )
    try:
        return client.verify()
    except ToolExecutionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get(
    "/v1/incidents",
    response_model=list[Incident],
    dependencies=[Depends(require_viewer)],
)
def incidents(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[Incident]:
    return store.list_incidents(limit)


@app.post(
    "/v1/incidents/{incident_id}/status",
    response_model=Incident,
)
def update_incident(
    incident_id: str,
    action: IncidentAction,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_analyst),
) -> Incident:
    incident = store.update_incident(
        incident_id, action.status, identity.email or identity.subject, action.note
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get(
    "/v1/containments",
    response_model=list[ContainmentRecord],
    dependencies=[Depends(require_viewer)],
)
def containments(
    active_only: bool = True,
    store: Store = Depends(get_store),
) -> list[ContainmentRecord]:
    return store.list_containments(active_only)


@app.post(
    "/v1/agents/{tenant_id}/{agent_id}/contain",
    response_model=ContainmentRecord,
)
def contain_agent(
    tenant_id: str,
    agent_id: str,
    request: ContainmentRequest,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_admin),
) -> ContainmentRecord:
    if request.mode.value == "restrict" and not request.allowed_tools:
        raise HTTPException(
            status_code=422, detail="restrict mode requires allowed_tools"
        )
    record = store.contain_agent(
        tenant_id,
        agent_id,
        request.mode,
        request.reason,
        identity.email or identity.subject,
        request.duration_seconds,
        request.allowed_tools,
        request.incident_id,
    )
    store.append_audit("agent_contained", record.model_dump(mode="json"))
    return record


@app.post(
    "/v1/containments/{containment_id}/release",
)
def release_containment(
    containment_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_admin),
) -> dict[str, bool]:
    released = store.release_containment(containment_id)
    if released:
        store.append_audit(
            "containment_released",
            {
                "containment_id": containment_id,
                "reviewer": identity.email or identity.subject,
                "note": action.note,
            },
        )
    return {"released": released}


@app.post(
    "/v1/agents/{tenant_id}/{agent_id}/release",
)
def release_agent(
    tenant_id: str,
    agent_id: str,
    request: ReleaseAgentRequest,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_admin),
) -> dict[str, bool]:
    reviewer = identity.email or identity.subject
    released = store.release_agent(tenant_id, agent_id, reviewer, request.note)
    if released:
        store.append_audit(
            "agent_released",
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "reviewer": reviewer,
            },
        )
    return {"released": released}


@app.get("/v1/audit", dependencies=[Depends(require_viewer)])
def audit(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[dict]:
    return store.recent_audit(limit)


@app.get(
    "/v1/activity",
    response_model=list[ActivityEvent],
    dependencies=[Depends(require_viewer)],
)
def activity(
    limit: int = Query(default=100, ge=1, le=500),
    tenant_id: str | None = None,
    agent_id: str | None = None,
    trace_id: str | None = None,
    store: Store = Depends(get_store),
) -> list[ActivityEvent]:
    return store.list_activity(limit, tenant_id, agent_id, trace_id)


@app.post("/v1/watch/tasks", response_model=WatchTaskRecord)
def create_watch_task(
    request: WatchTaskCreateRequest,
    principal: AgentPrincipal = Depends(require_agent),
    watch: WatchService = Depends(get_watch_service),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> WatchTaskRecord:
    if "watch:write" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Missing watch:write scope")
    _billing_guard(lambda: entitlements.require_watch_capacity(principal.tenant_id))
    try:
        return watch.create_task(principal, request)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/watch/events")
def ingest_watch_event(
    request: WatchEventRequest,
    principal: AgentPrincipal = Depends(require_agent),
    watch: WatchService = Depends(get_watch_service),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> dict[str, object]:
    if "watch:write" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Missing watch:write scope")
    _billing_guard(lambda: entitlements.require_watch_capacity(principal.tenant_id))
    try:
        event, findings = watch.ingest(principal, request)
    except WatchTaskNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"event": event, "findings": findings, "monitor_only": watch.monitor_only}


@app.post("/v1/watch/otel/v1/spans", response_model=OTelGenAIIngestResult)
def ingest_otel_genai_spans(
    request: OTelGenAIIngestRequest,
    principal: AgentPrincipal = Depends(require_agent),
    watch: WatchService = Depends(get_watch_service),
    store: Store = Depends(get_store),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> OTelGenAIIngestResult:
    """Accept a privacy-minimised subset of OpenTelemetry GenAI span metadata."""
    if "watch:write" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Missing watch:write scope")
    _billing_guard(lambda: entitlements.require_watch_capacity(principal.tenant_id))
    accepted = 0
    rejected = 0
    task_ids: set[str] = set()
    for span in request.spans:
        attributes = span.attributes
        task_id = str(
            attributes.get("sentinelgate.task.id")
            or attributes.get("gen_ai.conversation.id")
            or span.trace_id
        )
        session_id = str(attributes.get("gen_ai.conversation.id") or span.trace_id)
        tool_name_value = attributes.get("gen_ai.tool.name")
        tool_name = str(tool_name_value) if tool_name_value else None
        try:
            if (
                store.get_watch_task(task_id, principal.tenant_id, principal.agent_id)
                is None
            ):
                watch.create_task(
                    principal,
                    WatchTaskCreateRequest(
                        task_id=task_id,
                        description=str(
                            attributes.get("sentinelgate.task.description")
                            or f"OpenTelemetry trace {span.trace_id}"
                        ),
                    ),
                )
            watch.ingest(
                principal,
                WatchEventRequest(
                    task_id=task_id,
                    session_id=session_id,
                    event_type=(
                        WatchEventType.TOOL_CALL
                        if tool_name
                        else WatchEventType.HEARTBEAT
                    ),
                    tool_name=tool_name,
                    outcome=span.status,
                    error_code=("OTEL_SPAN_ERROR" if span.status == "error" else None),
                    call_fingerprint=(
                        store.metadata_fingerprint(tool_name) if tool_name else None
                    ),
                    input_tokens=int(attributes.get("gen_ai.usage.input_tokens", 0)),
                    output_tokens=int(attributes.get("gen_ai.usage.output_tokens", 0)),
                    duration_ms=span.duration_ms,
                ),
            )
            accepted += 1
            task_ids.add(task_id)
        except (ValueError, TypeError):
            rejected += 1
    return OTelGenAIIngestResult(
        accepted=accepted, rejected=rejected, task_ids=sorted(task_ids)
    )


@app.get(
    "/v1/watch/summary",
    response_model=WatchSummary,
    dependencies=[Depends(require_viewer)],
)
def watch_summary(
    tenant_id: str | None = None,
    store: Store = Depends(get_store),
) -> WatchSummary:
    return store.watch_summary(tenant_id)


@app.get("/v1/watch/baselines", dependencies=[Depends(require_analyst)])
def watch_baselines(
    minimum_tasks: int = Query(default=5, ge=2, le=100),
    store: Store = Depends(get_store),
) -> dict[str, object]:
    """Build transparent shadow baselines from completed, finding-free tasks."""
    groups: dict[tuple[str, str, str], list[WatchTaskRecord]] = {}
    for task in store.list_watch_tasks(limit=500):
        if task.status != "completed" or task.completed_at is None:
            continue
        if store.list_watch_findings(limit=1, task_id=task.task_id):
            continue
        groups.setdefault(
            (task.tenant_id, task.agent_id, task.profile.value), []
        ).append(task)
    baselines: list[dict[str, object]] = []
    for (tenant_id, agent_id, profile), tasks in sorted(groups.items()):
        if len(tasks) < minimum_tasks:
            continue
        call_counts: list[int] = []
        costs: list[float] = []
        durations: list[float] = []
        tool_counts: dict[str, int] = {}
        for task in tasks:
            events = store.list_watch_events(
                task.task_id, tenant_id, agent_id, limit=500
            )
            calls = [
                item for item in events if item.event_type is WatchEventType.TOOL_CALL
            ]
            call_counts.append(len(calls))
            costs.append(task.estimated_cost_usd)
            durations.append((task.completed_at - task.created_at).total_seconds())
            for event in calls:
                if event.tool_name:
                    tool_counts[event.tool_name] = (
                        tool_counts.get(event.tool_name, 0) + 1
                    )

        def percentile(values: list[float | int], fraction: float) -> float:
            ordered = sorted(float(item) for item in values)
            return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]

        baselines.append(
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "profile": profile,
                "sample_tasks": len(tasks),
                "median_tool_calls": statistics.median(call_counts),
                "p95_tool_calls": percentile(call_counts, 0.95),
                "median_cost_usd": statistics.median(costs),
                "p95_cost_usd": percentile(costs, 0.95),
                "p95_duration_seconds": percentile(durations, 0.95),
                "tool_distribution": dict(sorted(tool_counts.items())),
                "mode": "shadow",
            }
        )
    return {
        "minimum_tasks": minimum_tasks,
        "baselines": baselines,
        "automatic_blocking": False,
        "claim_boundary": "Only completed finding-free mediated tasks contribute.",
    }


@app.get(
    "/v1/watch/tasks",
    response_model=list[WatchTaskRecord],
    dependencies=[Depends(require_viewer)],
)
def watch_tasks(
    limit: int = Query(default=100, ge=1, le=500),
    tenant_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = Query(
        default=None, pattern=r"^(active|paused|completed|failed|cancelled)$"
    ),
    workflow_id: str | None = None,
    store: Store = Depends(get_store),
) -> list[WatchTaskRecord]:
    return store.list_watch_tasks(limit, tenant_id, agent_id, status, workflow_id)


@app.get(
    "/v1/watch/tasks/{task_id}/events",
    response_model=list[WatchEventRecord],
    dependencies=[Depends(require_viewer)],
)
def watch_task_events(
    task_id: str,
    limit: int = Query(default=200, ge=1, le=500),
    tenant_id: str | None = None,
    agent_id: str | None = None,
    store: Store = Depends(get_store),
) -> list[WatchEventRecord]:
    return store.list_watch_events(task_id, tenant_id, agent_id, limit)


@app.get(
    "/v1/watch/tasks/{task_id}/progress",
    response_model=WatchProgress,
    dependencies=[Depends(require_viewer)],
)
def watch_task_progress(
    task_id: str,
    tenant_id: str,
    agent_id: str | None = None,
    watch: WatchService = Depends(get_watch_service),
) -> WatchProgress:
    try:
        return watch.progress(task_id, tenant_id, agent_id)
    except WatchTaskNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get(
    "/v1/watch/findings",
    response_model=list[WatchFinding],
    dependencies=[Depends(require_viewer)],
)
def watch_findings(
    limit: int = Query(default=100, ge=1, le=500),
    tenant_id: str | None = None,
    agent_id: str | None = None,
    task_id: str | None = None,
    status: str | None = Query(default=None, pattern=r"^(open|acknowledged|resolved)$"),
    store: Store = Depends(get_store),
) -> list[WatchFinding]:
    return store.list_watch_findings(limit, tenant_id, agent_id, task_id, status)


@app.post("/v1/watch/findings/{finding_id}/status", response_model=WatchFinding)
def update_watch_finding(
    finding_id: str,
    action: WatchFindingAction,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_analyst),
) -> WatchFinding:
    reviewer = identity.email or identity.subject
    finding = store.update_watch_finding(finding_id, action, reviewer)
    if finding is None:
        raise HTTPException(status_code=404, detail="Watch finding not found")
    store.append_audit(
        "watch_finding_status_changed",
        {
            "finding_id": finding_id,
            "status": action.status,
            "reviewer": reviewer,
            "note": action.note,
        },
    )
    return finding


@app.get("/v1/watch/schema/event", dependencies=[Depends(require_viewer)])
def watch_event_schema() -> dict[str, object]:
    """Published contract for runtime event producers."""
    return WatchEventRequest.model_json_schema()


@app.post(
    "/v1/watch/tasks/{task_id}/intelligence",
    response_model=WatchIntelligenceResult,
)
def analyze_watch_task(
    task_id: str,
    request: WatchIntelligenceRequest,
    intelligence: WatchIntelligenceService = Depends(get_watch_intelligence),
    entitlements: EntitlementService = Depends(get_entitlements),
    _identity: AdminIdentity = Depends(require_analyst),
) -> WatchIntelligenceResult:
    _billing_guard(lambda: entitlements.require_llm_capacity(request.tenant_id))
    try:
        return intelligence.analyze(
            task_id,
            request.tenant_id,
            include_description=request.include_task_description,
        )
    except WatchIntelligenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get(
    "/v1/watch/response-policies",
    response_model=list[ResponsePolicy],
    dependencies=[Depends(require_analyst)],
)
def response_policies(
    tenant_id: str,
    store: Store = Depends(get_store),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> list[ResponsePolicy]:
    _billing_guard(lambda: entitlements.require_feature(tenant_id, "watch_response"))
    return store.list_response_policies(tenant_id)


@app.put("/v1/watch/response-policies", response_model=ResponsePolicy)
def configure_response_policy(
    request: ResponsePolicyRequest,
    store: Store = Depends(get_store),
    entitlements: EntitlementService = Depends(get_entitlements),
    identity: AdminIdentity = Depends(require_admin),
) -> ResponsePolicy:
    _billing_guard(
        lambda: entitlements.require_feature(request.tenant_id, "watch_response")
    )
    policy = ResponsePolicy(
        tenant_id=request.tenant_id,
        finding_code=request.finding_code,
        minimum_confidence=request.minimum_confidence,
        enabled=request.enabled,
        updated_by=identity.email or identity.subject,
        updated_at=utc_now(),
    )
    stored = store.upsert_response_policy(policy)
    store.append_audit(
        "watch_response_policy_updated",
        stored.model_dump(mode="json"),
    )
    return stored


@app.post(
    "/v1/respond/replay",
    response_model=WatchReplayResult,
    dependencies=[Depends(require_analyst)],
)
def replay_watch_rules(
    request: WatchReplayRequest,
    respond: RespondService = Depends(get_respond_service),
    entitlements: EntitlementService = Depends(get_entitlements),
) -> WatchReplayResult:
    if entitlements.enforcement_enabled:
        if request.tenant_id is None:
            raise HTTPException(
                status_code=422, detail="tenant_id is required for billing"
            )
        _billing_guard(
            lambda: entitlements.require_feature(
                request.tenant_id or "", "counterfactual_replay"
            )
        )
    return respond.replay(request)


@app.get(
    "/v1/respond/flight-recorder/{task_id}",
    response_model=FlightRecorder,
    dependencies=[Depends(require_viewer)],
)
def flight_recorder(
    task_id: str,
    tenant_id: str,
    agent_id: str | None = None,
    respond: RespondService = Depends(get_respond_service),
) -> FlightRecorder:
    try:
        return respond.flight_recorder(task_id, tenant_id, agent_id)
    except RespondError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get(
    "/v1/respond/plans",
    response_model=list[InterventionPlan],
    dependencies=[Depends(require_viewer)],
)
def intervention_plans(
    limit: int = Query(default=100, ge=1, le=500),
    tenant_id: str | None = None,
    task_id: str | None = None,
    status: str | None = Query(
        default=None,
        pattern=r"^(proposed|approved|rejected|executing|executed|failed)$",
    ),
    store: Store = Depends(get_store),
) -> list[InterventionPlan]:
    return store.list_intervention_plans(limit, tenant_id, task_id, status)


@app.post("/v1/respond/plans/{plan_id}/decision", response_model=InterventionPlan)
def decide_intervention_plan(
    plan_id: str,
    request: InterventionActionRequest,
    respond: RespondService = Depends(get_respond_service),
    identity: AdminIdentity = Depends(require_approver),
) -> InterventionPlan:
    try:
        return respond.decide_plan(
            plan_id,
            request.decision,
            identity.email or identity.subject,
            request.note,
        )
    except RespondError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/respond/plans/{plan_id}/execute", response_model=InterventionPlan)
def execute_intervention_plan(
    plan_id: str,
    request: InterventionActionRequest,
    respond: RespondService = Depends(get_respond_service),
    store: Store = Depends(get_store),
    entitlements: EntitlementService = Depends(get_entitlements),
    identity: AdminIdentity = Depends(require_approver),
) -> InterventionPlan:
    if request.decision != "approve":
        raise HTTPException(status_code=422, detail="Execution requires approve")
    plan = store.get_intervention_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Intervention plan not found")
    _billing_guard(
        lambda: entitlements.require_feature(plan.tenant_id, "watch_response")
    )
    try:
        return respond.execute_plan(
            plan_id, identity.email or identity.subject, request.note
        )
    except RespondError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/respond/tasks/{task_id}/recover", response_model=WatchTaskRecord)
def recover_watch_task(
    task_id: str,
    request: TaskRecoveryRequest,
    respond: RespondService = Depends(get_respond_service),
    entitlements: EntitlementService = Depends(get_entitlements),
    identity: AdminIdentity = Depends(require_approver),
) -> WatchTaskRecord:
    _billing_guard(
        lambda: entitlements.require_feature(request.tenant_id, "watch_response")
    )
    try:
        return respond.recover_task(
            request.tenant_id,
            task_id,
            identity.email or identity.subject,
            request.note,
        )
    except RespondError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/respond/sessions/revoke")
def revoke_watch_session(
    request: SessionRevocationRequest,
    respond: RespondService = Depends(get_respond_service),
    entitlements: EntitlementService = Depends(get_entitlements),
    identity: AdminIdentity = Depends(require_approver),
) -> dict[str, int]:
    _billing_guard(
        lambda: entitlements.require_feature(request.tenant_id, "watch_response")
    )
    try:
        count = respond.revoke_session(
            request.tenant_id,
            request.task_id,
            request.session_id,
            identity.email or identity.subject,
            request.note,
        )
    except RespondError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"revoked_tokens": count}


@app.get(
    "/v1/traces",
    response_model=list[TraceSummary],
    dependencies=[Depends(require_viewer)],
)
def traces(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[TraceSummary]:
    return store.list_trace_summaries(limit)


@app.get(
    "/v1/traces/{trace_id}/lineage",
    response_model=list[LineageRecord],
    dependencies=[Depends(require_viewer)],
)
def trace_lineage(
    trace_id: str,
    tenant_id: str | None = None,
    store: Store = Depends(get_store),
) -> list[LineageRecord]:
    return store.list_lineage(trace_id, tenant_id)


@app.get("/v1/metrics", dependencies=[Depends(require_viewer)])
def metrics(store: Store = Depends(get_store)) -> dict[str, int]:
    return store.metrics()


@app.get("/v1/system/status", dependencies=[Depends(require_viewer)])
def system_status(
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    metrics = store.metrics()
    return {
        "version": app.version,
        "environment": settings.environment,
        "enforcement_mode": settings.enforcement_mode.value,
        "database_backend": store.backend,
        "audit_chain_valid": store.verify_audit_chain(),
        "runtime": runtime_telemetry.snapshot(),
        "workers": store.worker_status(),
        "outbox": {
            "pending": metrics["notification_jobs_pending"],
            "dead": metrics["notification_jobs_dead"],
            "recent_jobs": store.list_outbox(20),
        },
    }


@app.get("/v1/work/jobs", dependencies=[Depends(require_analyst)])
def work_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[dict[str, object]]:
    return store.list_outbox(limit)


@app.get("/v1/benchmarks", dependencies=[Depends(require_viewer)])
def benchmark_evidence(settings: Settings = Depends(get_settings)) -> dict[str, object]:
    documents: list[dict[str, object]] = []
    for name in (
        "watch-foundation-v0.15.json",
        "watch-beta-v0.14.json",
        "benchmark-v0.10.json",
        "http-benchmark-v0.10.json",
        "adversarial-v0.10.json",
    ):
        path = settings.evidence_path / name
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        documents.append({"name": name, "evidence": payload})
    return {
        "release": app.version,
        "documents": documents,
        "claim_boundary": (
            "Project-authored regression and adversarial evidence. HTTP numbers are "
            "environment-specific and are not independent product validation."
        ),
    }


@app.get("/v1/reports/security", dependencies=[Depends(require_viewer)])
def security_report(
    limit: int = Query(default=500, ge=1, le=5000),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    return security_evidence_report(store, settings, limit)


@app.get(
    "/v1/reports/audit.csv",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_viewer)],
)
def audit_csv(
    limit: int = Query(default=500, ge=1, le=5000),
    store: Store = Depends(get_store),
) -> PlainTextResponse:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "created_at",
            "event_type",
            "payload",
            "previous_hash",
            "event_hash",
        ],
    )
    writer.writeheader()
    for event in reversed(store.recent_audit(limit)):
        writer.writerow(
            event | {"payload": json.dumps(event["payload"], sort_keys=True)}
        )
    return PlainTextResponse(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelgate-audit.csv"},
    )


@app.get(
    "/metrics", response_class=PlainTextResponse, dependencies=[Depends(require_viewer)]
)
def prometheus_metrics(store: Store = Depends(get_store)) -> str:
    database_metrics = "\n".join(
        f"sentinelgate_{name} {value}" for name, value in store.metrics().items()
    )
    return runtime_telemetry.prometheus() + database_metrics + "\n"


@app.get("/v1/billing/plans")
def billing_plans() -> list[dict[str, object]]:
    return [
        {
            "id": definition.plan.value,
            "name": definition.name,
            "monthly_price_gbp": definition.monthly_price_gbp,
            "included_agents": definition.included_agents,
            "decision_limit_monthly": definition.decision_limit_monthly,
            "watch_event_limit_monthly": definition.watch_event_limit_monthly,
            "llm_analysis_limit_monthly": definition.llm_analysis_limit_monthly,
            "retention_days": definition.retention_days,
            "features": sorted(definition.features),
        }
        for definition in PLAN_CATALOGUE.values()
    ]


@app.get(
    "/v1/billing/entitlements/{tenant_id}",
    response_model=EntitlementSnapshot,
    dependencies=[Depends(require_viewer)],
)
def billing_entitlements(
    tenant_id: str,
    entitlements: EntitlementService = Depends(get_entitlements),
    identity: AdminIdentity = Depends(require_viewer),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> EntitlementSnapshot:
    _require_tenant_access(identity, tenant_id, settings, saas)
    return entitlements.snapshot(tenant_id)


@app.post("/v1/billing/checkout", response_model=BillingSessionResponse)
def billing_checkout(
    request: BillingCheckoutRequest,
    identity: AdminIdentity = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> BillingSessionResponse:
    _require_tenant_access(
        identity,
        request.tenant_id,
        settings,
        saas,
        {MembershipRole.OWNER, MembershipRole.ADMINISTRATOR},
    )
    try:
        url = get_billing_client().create_checkout(
            tenant_id=request.tenant_id,
            plan=request.plan,
            extra_agents=request.extra_agents,
            customer_email=request.customer_email,
        )
    except BillingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return BillingSessionResponse(url=url)


@app.post("/v1/billing/portal", response_model=BillingSessionResponse)
def billing_portal(
    request: BillingPortalRequest,
    store: Store = Depends(get_store),
    identity: AdminIdentity = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    saas: SaaSIdentityService = Depends(get_saas_identity),
) -> BillingSessionResponse:
    _require_tenant_access(
        identity,
        request.tenant_id,
        settings,
        saas,
        {MembershipRole.OWNER, MembershipRole.ADMINISTRATOR},
    )
    subscription = store.get_tenant_subscription(request.tenant_id)
    if subscription is None or not subscription.stripe_customer_id:
        raise HTTPException(
            status_code=404, detail="No Stripe customer for this tenant"
        )
    try:
        url = get_billing_client().create_portal(subscription.stripe_customer_id)
    except BillingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return BillingSessionResponse(url=url)


@app.post("/v1/billing/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict[str, bool]:
    if settings.billing_mode == "disabled" or not settings.stripe_webhook_secret:
        raise HTTPException(status_code=404, detail="Billing webhook is disabled")
    payload = await request.body()
    if len(payload) > 1_000_000:
        raise HTTPException(status_code=413, detail="Webhook payload is too large")
    try:
        event = StripeWebhookVerifier(settings.stripe_webhook_secret).verify(
            payload, request.headers.get("stripe-signature", "")
        )
        processed = BillingWebhookProcessor(store).process(event)
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"received": True, "processed": processed}


@app.get("/", response_class=HTMLResponse)
def landing(settings: Settings = Depends(get_settings)) -> str:
    return branded_page(LANDING_HTML, settings.product_name)


@app.get("/pricing", response_class=HTMLResponse)
def pricing(settings: Settings = Depends(get_settings)) -> str:
    return branded_page(LANDING_HTML, settings.product_name)


@app.get("/learn", response_class=HTMLResponse)
def learn(settings: Settings = Depends(get_settings)) -> str:
    return branded_page(LEARN_HTML, settings.product_name)


@app.get("/console", response_class=HTMLResponse)
@app.get("/console/{section}", response_class=HTMLResponse)
def console(
    section: str = "overview", settings: Settings = Depends(get_settings)
) -> str:
    allowed = {
        "overview",
        "watch",
        "respond",
        "traces",
        "approvals",
        "agents",
        "incidents",
        "connectors",
        "mcp-security",
        "policy",
        "audit",
        "reports",
        "onboarding",
        "system",
        "benchmarks",
        "billing",
        "login",
    }
    if section not in allowed:
        raise HTTPException(status_code=404, detail="Console page not found")
    return console_page(section, settings.product_name)
