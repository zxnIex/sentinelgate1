import base64
import binascii
import csv
import hashlib
import hmac
import io
import json
import secrets
import time
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote, urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from sentinelgate.admin_identity import (
    AdminIdentity,
    AdminIdentityError,
    OIDCAdminVerifier,
)
from sentinelgate.dashboard import LANDING_HTML, console_page
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
    ContainmentRecord,
    ContainmentRequest,
    DeclassificationRequest,
    ExecutionResult,
    Incident,
    IncidentAction,
    IssueAgentTokenRequest,
    LineageRecord,
    MCPManifestInspectionRequest,
    MCPManifestInspectionResult,
    PolicyDecision,
    PolicyReplayRequest,
    PolicyReplayResult,
    ProvenanceAttestation,
    ProvenanceAttestRequest,
    ReleaseAgentRequest,
    SimulationRequest,
    StructuredProvenanceAttestRequest,
    StructuredProvenanceDeriveRequest,
    TokenResponse,
    ToolCallRequest,
    TraceSummary,
    utc_now,
)
from sentinelgate.policy import PolicyConfigurationError, PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.reporting import security_evidence_report
from sentinelgate.service import GatewayService
from sentinelgate.settings import Settings, get_settings
from sentinelgate.storage import StorageIntegrityError, Store
from sentinelgate.telemetry import runtime_telemetry
from sentinelgate.upstream_mcp import (
    UpstreamMCPError,
    UpstreamMCPManager,
    handle_upstream_mcp,
)

app = FastAPI(
    title="SentinelGate",
    version="0.10.0",
    description="Identity-aware, fail-closed security gateway for AI-agent tool calls.",
)
app.mount(
    "/assets",
    StaticFiles(directory=Path(__file__).with_name("static"), check_dir=True),
    name="assets",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    started = time.perf_counter()
    status = 500
    try:
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
    if request.url.path == "/" or request.url.path.startswith("/console"):
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
    credentials: HTTPAuthorizationCredentials | None = Depends(admin_bearer),
    settings: Settings = Depends(get_settings),
) -> AdminIdentity:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(status_code=401, detail="Administrator bearer token required")
    token = credentials.credentials
    if settings.admin_auth_mode in {"shared", "hybrid"} and hmac.compare_digest(
        token, settings.admin_token
    ):
        return AdminIdentity(
            subject="shared-development-administrator",
            email=None,
            roles=frozenset({"administrator"}),
        )
    verifier = get_admin_verifier()
    if verifier is None:
        raise HTTPException(status_code=401, detail="Invalid administrator token")
    try:
        identity = verifier.verify(token)
    except AdminIdentityError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return identity


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
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(signing_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()
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
        if not isinstance(payload, dict) or int(payload["expires_at"]) < int(time.time()):
            raise ValueError("expired")
        return payload
    except (binascii.Error, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="OIDC login state is invalid") from exc


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


@app.get("/v1/auth/config")
def auth_config(settings: Settings = Depends(get_settings)) -> dict[str, object]:
    browser_sso = _browser_oidc_configured(settings)
    return {
        "mode": settings.admin_auth_mode,
        "federated_sign_in": settings.admin_auth_mode in {"oidc", "hybrid"},
        "development_token": settings.admin_auth_mode in {"shared", "hybrid"},
        "self_service_signup": False,
        "browser_sso": browser_sso,
        "login_url": "/auth/login" if browser_sso else None,
        "signup_reason": (
            "SentinelGate delegates operator lifecycle and MFA to the customer's "
            "identity provider instead of creating a second identity directory."
        ),
    }


@app.get("/auth/login")
def oidc_login(
    next_path: str = Query(default="/console", alias="next"),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if not _browser_oidc_configured(settings):
        raise HTTPException(status_code=404, detail="Browser OIDC sign-in is not configured")
    if not next_path.startswith("/console") or next_path.startswith("//"):
        next_path = "/console"
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
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
) -> RedirectResponse:
    if not _browser_oidc_configured(settings):
        raise HTTPException(status_code=404, detail="Browser OIDC sign-in is not configured")
    cookie = request.cookies.get("sentinelgate_oidc_state")
    if not cookie:
        raise HTTPException(status_code=400, detail="OIDC login state cookie is missing")
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
        raise HTTPException(status_code=401, detail="OIDC code exchange failed") from exc
    store.append_audit(
        "operator_oidc_login",
        {
            "subject": identity.subject,
            "email": identity.email,
            "roles": sorted(identity.roles),
        },
    )
    target = str(login_state.get("next", "/console"))
    response = RedirectResponse(
        f"{target}#access_token={quote(access_token, safe='')}", status_code=303
    )
    response.delete_cookie("sentinelgate_oidc_state", path="/auth")
    return response


@app.get("/v1/session", dependencies=[Depends(require_viewer)])
def session(identity: AdminIdentity = Depends(_operator_identity)) -> dict[str, object]:
    return {
        "subject": identity.subject,
        "email": identity.email,
        "roles": sorted(identity.roles),
    }


@app.get("/health")
def health(store: Store = Depends(get_store)) -> dict[str, object]:
    return {
        "status": "ok",
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
        raise HTTPException(status_code=503, detail={"status": "not_ready", "checks": checks})
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
            "status": "passing" if settings.admin_auth_mode in {"oidc", "hybrid"} else "review",
            "detail": settings.admin_auth_mode,
            "required_for_production": True,
        },
        {
            "id": "notifications",
            "label": "Approval delivery",
            "status": (
                "passing" if webhook_enabled and any(w["status"] == "online" for w in workers)
                else "review" if webhook_enabled else "optional"
            ),
            "detail": (
                "durable worker online" if webhook_enabled and workers
                else "webhook configured; start worker" if webhook_enabled
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


@app.post("/mcp")
def mcp_endpoint(
    payload: dict,
    principal: AgentPrincipal = Depends(require_agent),
    service: GatewayService = Depends(get_service),
) -> dict:
    return handle_mcp(payload, principal, service)


@app.post("/mcp/upstream/{server_id}")
def upstream_mcp_endpoint(
    server_id: str,
    payload: dict,
    principal: AgentPrincipal = Depends(require_agent),
    service: GatewayService = Depends(get_service),
    manager: UpstreamMCPManager = Depends(get_upstream_mcp),
) -> dict:
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
    if not server_id or len(server_id) > 128 or not all(
        character.isalnum() or character in "_.:-" for character in server_id
    ):
        raise HTTPException(status_code=422, detail="Invalid MCP server identifier")
    return inspect_manifest(server_id, request, store)


@app.get("/v1/mcp/servers", dependencies=[Depends(require_viewer)])
def mcp_servers(store: Store = Depends(get_store)) -> list[dict]:
    return store.list_mcp_tool_baselines()


@app.post(
    "/v1/tokens/agents",
    response_model=TokenResponse,
    dependencies=[Depends(require_admin)],
)
def issue_agent_token(
    request: IssueAgentTokenRequest,
    signer: TokenSigner = Depends(get_signer),
    store: Store = Depends(get_store),
) -> TokenResponse:
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
) -> list[AgentRecord]:
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
) -> dict[str, int]:
    count = store.revoke_agent_tokens(tenant_id, agent_id, action.note or "Administrative revocation")
    store.append_audit(
        "agent_tokens_revoked",
        {"tenant_id": tenant_id, "agent_id": agent_id, "reviewer": identity.email or identity.subject, "count": count},
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


@app.post(
    "/v1/provenance/attest-structured", response_model=ProvenanceAttestation
)
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


@app.post(
    "/v1/provenance/derive-structured", response_model=ProvenanceAttestation
)
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
        raise HTTPException(status_code=403, detail="Label is not declassifiable by policy")
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
) -> PolicyDecision:
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
) -> ExecutionResult:
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
            "status": "configured" if settings.knowledge_path.is_dir() else "unavailable",
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
        raise HTTPException(status_code=422, detail="restrict mode requires allowed_tools")
    record = store.contain_agent(
        tenant_id, agent_id, request.mode, request.reason, identity.email or identity.subject,
        request.duration_seconds, request.allowed_tools, request.incident_id,
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
            {"containment_id": containment_id, "reviewer": identity.email or identity.subject, "note": action.note},
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
            "id", "created_at", "event_type", "payload",
            "previous_hash", "event_hash",
        ],
    )
    writer.writeheader()
    for event in reversed(store.recent_audit(limit)):
        writer.writerow(event | {"payload": json.dumps(event["payload"], sort_keys=True)})
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


@app.get("/", response_class=HTMLResponse)
def landing() -> str:
    return LANDING_HTML


@app.get("/console", response_class=HTMLResponse)
@app.get("/console/{section}", response_class=HTMLResponse)
def console(section: str = "overview") -> str:
    allowed = {
        "overview", "traces", "approvals", "agents", "incidents",
        "connectors", "mcp-security", "policy", "audit", "reports",
        "onboarding", "system", "benchmarks", "login",
    }
    if section not in allowed:
        raise HTTPException(status_code=404, detail="Console page not found")
    return console_page(section)
