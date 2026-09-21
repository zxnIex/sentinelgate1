import csv
import hmac
import io
import json
from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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
    TokenResponse,
    ToolCallRequest,
    TraceSummary,
    utc_now,
)
from sentinelgate.notifications import ApprovalNotifier
from sentinelgate.policy import PolicyConfigurationError, PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.reporting import security_evidence_report
from sentinelgate.service import GatewayService
from sentinelgate.settings import Settings, get_settings
from sentinelgate.storage import StorageIntegrityError, Store
from sentinelgate.upstream_mcp import (
    UpstreamMCPError,
    UpstreamMCPManager,
    handle_upstream_mcp,
)

app = FastAPI(
    title="SentinelGate",
    version="0.7.0",
    description="Identity-aware, fail-closed security gateway for AI-agent tool calls.",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path == "/" or request.url.path.startswith("/console"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
    return response

admin_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="AdminBearer",
    description="Raw SENTINEL_ADMIN_TOKEN value. Swagger adds the Bearer prefix.",
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
        settings.database_path,
        settings.audit_signing_key,
        settings.data_encryption_key,
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
        ApprovalNotifier(
            settings.approval_webhook_url,
            settings.approval_webhook_secret,
            settings.console_public_url,
        ),
    )


@lru_cache
def get_upstream_mcp() -> UpstreamMCPManager:
    settings = get_settings()
    return UpstreamMCPManager(settings.mcp_upstreams_path, get_store())


def require_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(admin_bearer),
    settings: Settings = Depends(get_settings),
) -> None:
    if (
        credentials is None
        or credentials.scheme.casefold() != "bearer"
        or not hmac.compare_digest(credentials.credentials, settings.admin_token)
    ):
        raise HTTPException(status_code=401, detail="Invalid admin token")


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


@app.get("/health")
def health(store: Store = Depends(get_store)) -> dict[str, object]:
    return {
        "status": "ok",
        "version": app.version,
        "enforcement_mode": get_settings().enforcement_mode.value,
        "audit_chain_valid": store.verify_audit_chain(),
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


@app.get("/v1/mcp/servers", dependencies=[Depends(require_admin)])
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
    dependencies=[Depends(require_admin)],
)
def agents(
    tenant_id: str | None = None,
    store: Store = Depends(get_store),
) -> list[AgentRecord]:
    return store.list_agents(tenant_id)


@app.post(
    "/v1/agents/{tenant_id}/{agent_id}/revoke",
    dependencies=[Depends(require_admin)],
)
def revoke_agent(
    tenant_id: str,
    agent_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
) -> dict[str, int]:
    count = store.revoke_agent_tokens(tenant_id, agent_id, action.note or "Administrative revocation")
    store.append_audit(
        "agent_tokens_revoked",
        {"tenant_id": tenant_id, "agent_id": agent_id, "reviewer": action.reviewer, "count": count},
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
    dependencies=[Depends(require_admin)],
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
    dependencies=[Depends(require_admin)],
)
def approve(
    approval_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
) -> ApprovalRecord:
    record = store.resolve_approval(
        approval_id, "approved", action.reviewer, action.note
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
    dependencies=[Depends(require_admin)],
)
def reject(
    approval_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
) -> ApprovalRecord:
    record = store.resolve_approval(
        approval_id, "rejected", action.reviewer, action.note
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
    dependencies=[Depends(require_admin)],
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
    dependencies=[Depends(require_admin)],
)
def simulate(
    request: SimulationRequest,
    service: GatewayService = Depends(get_service),
) -> list[PolicyDecision]:
    return service.simulate(request)


@app.post(
    "/v1/policy/replay",
    response_model=PolicyReplayResult,
    dependencies=[Depends(require_admin)],
)
def replay_policy(
    request: PolicyReplayRequest,
    service: GatewayService = Depends(get_service),
) -> PolicyReplayResult:
    try:
        return service.replay_policy(request)
    except (PolicyConfigurationError, StorageIntegrityError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/policy", dependencies=[Depends(require_admin)])
def current_policy(service: GatewayService = Depends(get_service)) -> dict:
    return service.policy.as_mapping()


@app.get("/v1/connectors", dependencies=[Depends(require_admin)])
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
    dependencies=[Depends(require_admin)],
)
def incidents(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[Incident]:
    return store.list_incidents(limit)


@app.post(
    "/v1/incidents/{incident_id}/status",
    response_model=Incident,
    dependencies=[Depends(require_admin)],
)
def update_incident(
    incident_id: str,
    action: IncidentAction,
    store: Store = Depends(get_store),
) -> Incident:
    incident = store.update_incident(incident_id, action.status, action.reviewer, action.note)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get(
    "/v1/containments",
    response_model=list[ContainmentRecord],
    dependencies=[Depends(require_admin)],
)
def containments(
    active_only: bool = True,
    store: Store = Depends(get_store),
) -> list[ContainmentRecord]:
    return store.list_containments(active_only)


@app.post(
    "/v1/agents/{tenant_id}/{agent_id}/contain",
    response_model=ContainmentRecord,
    dependencies=[Depends(require_admin)],
)
def contain_agent(
    tenant_id: str,
    agent_id: str,
    request: ContainmentRequest,
    store: Store = Depends(get_store),
) -> ContainmentRecord:
    if request.mode.value == "restrict" and not request.allowed_tools:
        raise HTTPException(status_code=422, detail="restrict mode requires allowed_tools")
    record = store.contain_agent(
        tenant_id, agent_id, request.mode, request.reason, request.reviewer,
        request.duration_seconds, request.allowed_tools, request.incident_id,
    )
    store.append_audit("agent_contained", record.model_dump(mode="json"))
    return record


@app.post(
    "/v1/containments/{containment_id}/release",
    dependencies=[Depends(require_admin)],
)
def release_containment(
    containment_id: str,
    action: ApprovalAction,
    store: Store = Depends(get_store),
) -> dict[str, bool]:
    released = store.release_containment(containment_id)
    if released:
        store.append_audit(
            "containment_released",
            {"containment_id": containment_id, "reviewer": action.reviewer, "note": action.note},
        )
    return {"released": released}


@app.post(
    "/v1/agents/{tenant_id}/{agent_id}/release",
    dependencies=[Depends(require_admin)],
)
def release_agent(
    tenant_id: str,
    agent_id: str,
    request: ReleaseAgentRequest,
    store: Store = Depends(get_store),
) -> dict[str, bool]:
    released = store.release_agent(tenant_id, agent_id, request.reviewer, request.note)
    if released:
        store.append_audit(
            "agent_released",
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "reviewer": request.reviewer,
            },
        )
    return {"released": released}


@app.get("/v1/audit", dependencies=[Depends(require_admin)])
def audit(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[dict]:
    return store.recent_audit(limit)


@app.get(
    "/v1/activity",
    response_model=list[ActivityEvent],
    dependencies=[Depends(require_admin)],
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
    dependencies=[Depends(require_admin)],
)
def traces(
    limit: int = Query(default=100, ge=1, le=500),
    store: Store = Depends(get_store),
) -> list[TraceSummary]:
    return store.list_trace_summaries(limit)


@app.get(
    "/v1/traces/{trace_id}/lineage",
    response_model=list[LineageRecord],
    dependencies=[Depends(require_admin)],
)
def trace_lineage(
    trace_id: str,
    tenant_id: str | None = None,
    store: Store = Depends(get_store),
) -> list[LineageRecord]:
    return store.list_lineage(trace_id, tenant_id)


@app.get("/v1/metrics", dependencies=[Depends(require_admin)])
def metrics(store: Store = Depends(get_store)) -> dict[str, int]:
    return store.metrics()


@app.get("/v1/reports/security", dependencies=[Depends(require_admin)])
def security_report(
    limit: int = Query(default=500, ge=1, le=5000),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    return security_evidence_report(store, settings, limit)


@app.get(
    "/v1/reports/audit.csv",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_admin)],
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
    "/metrics", response_class=PlainTextResponse, dependencies=[Depends(require_admin)]
)
def prometheus_metrics(store: Store = Depends(get_store)) -> str:
    return (
        "\n".join(
            f"sentinelgate_{name} {value}" for name, value in store.metrics().items()
        )
        + "\n"
    )


@app.get("/", response_class=HTMLResponse)
def landing() -> str:
    return LANDING_HTML


@app.get("/console", response_class=HTMLResponse)
@app.get("/console/{section}", response_class=HTMLResponse)
def console(section: str = "overview") -> str:
    allowed = {
        "overview", "traces", "approvals", "agents", "incidents",
        "connectors", "mcp-security", "policy", "audit", "reports",
    }
    if section not in allowed:
        raise HTTPException(status_code=404, detail="Console page not found")
    return console_page(section)
