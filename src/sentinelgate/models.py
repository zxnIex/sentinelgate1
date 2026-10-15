from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

TaintLabel = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.:-]{1,64}$", max_length=64)]
JsonPointer = Annotated[
    str, Field(pattern=r"^(?:/(?:[^~/]|~[01])*)*$", max_length=1024)
]
TraceId = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$", max_length=128)]


def utc_now() -> datetime:
    return datetime.now(UTC)


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class EnforcementMode(StrEnum):
    OBSERVE = "observe"
    WARN = "warn"
    ENFORCE = "enforce"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    MIXED = "mixed"
    UNTRUSTED = "untrusted"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AgentPrincipal(BaseModel):
    agent_id: str
    tenant_id: str
    scopes: frozenset[str]
    token_id: str
    expires_at: datetime


class IssueAgentTokenRequest(BaseModel):
    agent_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    scopes: list[str] = Field(min_length=1, max_length=50)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    owner: str = Field(default="platform-admin", min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    token_id: str | None = None


class ProvenanceAttestRequest(BaseModel):
    source_id: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=100_000)
    trust: TrustLevel = TrustLevel.UNTRUSTED
    classification: DataClassification = DataClassification.PUBLIC
    labels: list[TaintLabel] = Field(default_factory=list, max_length=50)
    trace_id: TraceId | None = None


class ProvenanceAttestation(BaseModel):
    token: str
    content_digest: str
    trust: TrustLevel
    signals: list[str]
    classification: DataClassification = DataClassification.PUBLIC
    labels: list[TaintLabel] = Field(default_factory=list)
    lineage_id: str
    trace_id: TraceId | None = None
    expires_at: datetime
    field_taint: dict[JsonPointer, "FieldTaint"] = Field(default_factory=dict)


class FieldTaint(BaseModel):
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    trust: TrustLevel
    classification: DataClassification = DataClassification.PUBLIC
    labels: list[TaintLabel] = Field(default_factory=list, max_length=50)
    lineage_ids: list[str] = Field(default_factory=list, max_length=100)


class FieldProvenanceReference(BaseModel):
    token: str = Field(min_length=20, max_length=16_384)
    source_pointer: JsonPointer


class StructuredProvenanceAttestRequest(BaseModel):
    source_id: str = Field(min_length=1, max_length=256)
    value: Any
    trust: TrustLevel = TrustLevel.UNTRUSTED
    classification: DataClassification = DataClassification.PUBLIC
    labels: list[TaintLabel] = Field(default_factory=list, max_length=50)
    trace_id: TraceId | None = None
    field_overrides: dict[JsonPointer, dict[str, Any]] = Field(default_factory=dict)


class DerivationInput(BaseModel):
    value: Any
    reference: FieldProvenanceReference


class FieldDerivation(BaseModel):
    operation: str = Field(pattern=r"^(copy|concat|template|substring)$")
    inputs: list[str] = Field(min_length=1, max_length=50)
    separator: str = Field(default="", max_length=100)
    template: str = Field(default="", max_length=10_000)
    start: int | None = None
    end: int | None = None


class StructuredProvenanceDeriveRequest(BaseModel):
    source_id: str = Field(min_length=1, max_length=256)
    value: Any
    inputs: dict[str, DerivationInput] = Field(min_length=1, max_length=100)
    derivations: dict[JsonPointer, FieldDerivation] = Field(default_factory=dict)
    mode: str = Field(pattern=r"^(deterministic|llm)$")
    trace_id: TraceId


class DeclassificationRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    token: str = Field(min_length=20, max_length=16_384)
    paths: list[JsonPointer] = Field(min_length=1, max_length=100)
    remove_labels: list[TaintLabel] = Field(min_length=1, max_length=20)
    reviewer: str = Field(default="", max_length=128, description="Deprecated")
    reason: str = Field(min_length=10, max_length=1000)


class VerifiedProvenance(BaseModel):
    source_id: str
    content_digest: str
    trust: TrustLevel
    signals: list[str]
    classification: DataClassification = DataClassification.PUBLIC
    labels: list[TaintLabel] = Field(default_factory=list)
    lineage_id: str | None = None
    trace_id: TraceId | None = None
    parent_ids: list[str] = Field(default_factory=list)
    field_taint: dict[JsonPointer, FieldTaint] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    provenance_tokens: list[str] = Field(default_factory=list, max_length=50)
    field_provenance: dict[JsonPointer, list[FieldProvenanceReference]] = Field(
        default_factory=dict
    )
    purpose: str = Field(default="", max_length=1000)
    trace_id: TraceId = Field(default_factory=lambda: str(uuid4()))
    task_id: TraceId | None = None
    mcp_server_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")


class SecurityFinding(BaseModel):
    code: str
    severity: str
    path: str
    fingerprint: str


class PolicyDecision(BaseModel):
    request_id: str
    request_hash: str
    agent_id: str
    tenant_id: str
    decision: Decision
    reason_codes: list[str]
    risk: str
    policy_version: str
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    approval_id: str | None = None
    audit_event_id: str
    quarantined: bool = False
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    enforced: bool = True


class ApprovalAction(BaseModel):
    reviewer: str = Field(
        default="",
        max_length=128,
        description="Deprecated: reviewer identity is derived from the authenticated operator.",
    )
    note: str = Field(default="", max_length=1000)


class ApprovalRecord(BaseModel):
    id: str
    request: ToolCallRequest
    request_hash: str
    agent_id: str
    tenant_id: str
    scopes: list[str]
    status: str
    created_at: datetime
    expires_at: datetime
    resolved_at: datetime | None = None
    reviewer: str | None = None
    note: str = ""


class ExecutionResult(BaseModel):
    request_id: str
    status: str
    decision: PolicyDecision | None = None
    output: Any | None = None
    approval_id: str | None = None
    output_provenance_token: str | None = None
    classification: DataClassification | None = None
    taint_labels: list[str] = Field(default_factory=list)
    trace_id: TraceId | None = None
    field_taint: dict[JsonPointer, FieldTaint] = Field(default_factory=dict)


class SimulationRequest(BaseModel):
    agent_id: str
    tenant_id: str = "simulation"
    scopes: list[str]
    calls: list[ToolCallRequest] = Field(min_length=1, max_length=100)


class PolicyReplayRequest(BaseModel):
    policy: dict[str, Any] | None = None
    limit: int = Field(default=100, ge=1, le=500)


class PolicyReplayDecision(BaseModel):
    request_id: str
    trace_id: TraceId
    tool_name: str
    original_decision: Decision
    replayed_decision: Decision
    changed: bool
    reason_codes: list[str]


class PolicyReplayResult(BaseModel):
    policy_version: str
    evaluated: int
    changed: int
    allow: int
    deny: int
    require_approval: int
    decisions: list[PolicyReplayDecision]


class Incident(BaseModel):
    id: str
    tenant_id: str
    agent_id: str
    trace_id: TraceId
    severity: str
    summary: str
    event_count: int
    status: str
    first_seen: datetime
    last_seen: datetime


class IncidentAction(BaseModel):
    status: str = Field(pattern="^(open|investigating|contained|resolved)$")
    reviewer: str = Field(default="", max_length=128, description="Deprecated")
    note: str = Field(default="", max_length=1000)


class AgentRecord(BaseModel):
    tenant_id: str
    agent_id: str
    owner: str
    status: str
    scopes: list[str]
    created_at: datetime
    updated_at: datetime
    active_tokens: int = 0


class ContainmentMode(StrEnum):
    MONITOR = "monitor"
    RESTRICT = "restrict"
    QUARANTINE = "quarantine"
    REVOKE = "revoke"


class ContainmentRequest(BaseModel):
    mode: ContainmentMode
    reviewer: str = Field(default="", max_length=128, description="Deprecated")
    reason: str = Field(min_length=1, max_length=1000)
    duration_seconds: int = Field(default=900, ge=60, le=86400)
    allowed_tools: list[str] = Field(default_factory=list, max_length=50)
    incident_id: str | None = None


class ContainmentRecord(BaseModel):
    id: str
    tenant_id: str
    agent_id: str
    mode: ContainmentMode
    reason: str
    reviewer: str
    allowed_tools: list[str]
    incident_id: str | None = None
    created_at: datetime
    expires_at: datetime
    released_at: datetime | None = None


class ActivityEvent(BaseModel):
    tenant_id: str
    agent_id: str
    trace_id: str
    tool_name: str
    category: str
    decision: str
    created_at: datetime


class WatchProfile(StrEnum):
    RELAXED = "relaxed"
    BALANCED = "balanced"
    STRICT = "strict"


class WatchEventType(StrEnum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    PROGRESS = "progress"
    HEARTBEAT = "heartbeat"
    TASK_STATUS = "task_status"


class WatchTaskCreateRequest(BaseModel):
    task_id: TraceId = Field(default_factory=lambda: str(uuid4()))
    workflow_id: TraceId | None = None
    description: str = Field(min_length=1, max_length=2000)
    profile: WatchProfile = WatchProfile.BALANCED
    expected_tools: list[str] = Field(default_factory=list, max_length=50)
    success_criteria: list[str] = Field(default_factory=list, max_length=50)
    allow_multi_session: bool = False
    max_runtime_seconds: int = Field(default=3600, ge=60, le=604800)
    max_tool_calls: int = Field(default=250, ge=1, le=1_000_000)
    max_cost_usd: float = Field(default=10.0, ge=0, le=1_000_000)


class WatchTaskRecord(BaseModel):
    task_id: TraceId
    workflow_id: TraceId
    tenant_id: str
    agent_id: str
    description: str
    profile: WatchProfile
    expected_tools: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    allow_multi_session: bool = False
    max_runtime_seconds: int
    max_tool_calls: int
    max_cost_usd: float
    status: str
    event_count: int = 0
    estimated_cost_usd: float = 0.0
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None


class WatchEventRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: TraceId
    session_id: TraceId | None = None
    event_type: WatchEventType
    tool_name: str | None = Field(
        default=None, pattern=r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$"
    )
    outcome: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=128)
    call_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    progress_signal: str | None = Field(default=None, max_length=256)
    milestone_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    input_tokens: int = Field(default=0, ge=0, le=1_000_000_000)
    output_tokens: int = Field(default=0, ge=0, le=1_000_000_000)
    estimated_cost_usd: float = Field(default=0.0, ge=0, le=1_000_000)
    duration_ms: float | None = Field(default=None, ge=0, le=86_400_000)


class WatchEventRecord(WatchEventRequest):
    id: str
    tenant_id: str
    agent_id: str
    created_at: datetime


class WatchFinding(BaseModel):
    id: str
    tenant_id: str
    agent_id: str
    task_id: TraceId
    code: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str
    status: str
    occurrences: int
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    reviewer: str | None = None
    note: str = ""
    detector_type: str = Field(
        default="deterministic", pattern=r"^(deterministic|llm)$"
    )
    analysis_id: str | None = None


class InterventionAction(StrEnum):
    REVIEW_TASK = "review_task"
    PAUSE_TASK = "pause_task"
    RESTRICT_AGENT = "restrict_agent"
    QUARANTINE_AGENT = "quarantine_agent"


class InterventionPlan(BaseModel):
    id: str
    finding_id: str
    tenant_id: str
    agent_id: str
    task_id: TraceId
    action: InterventionAction
    rationale: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: str = Field(
        pattern=r"^(proposed|approved|rejected|executing|executed|failed)$"
    )
    created_at: datetime
    resolved_at: datetime | None = None
    reviewer: str | None = None
    note: str = ""


class InterventionActionRequest(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    note: str = Field(default="", max_length=1000)


class WatchReplayRequest(BaseModel):
    tenant_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    candidate_profile: WatchProfile
    task_ids: list[TraceId] = Field(default_factory=list, max_length=500)
    limit: int = Field(default=100, ge=1, le=500)


class WatchReplayTaskResult(BaseModel):
    task_id: TraceId
    current_codes: list[str]
    candidate_codes: list[str]
    added_codes: list[str]
    removed_codes: list[str]


class WatchReplayResult(BaseModel):
    evaluated_tasks: int
    changed_tasks: int
    candidate_profile: WatchProfile
    added_findings: int
    removed_findings: int
    results: list[WatchReplayTaskResult]


class FlightRecorder(BaseModel):
    task: WatchTaskRecord
    events: list[WatchEventRecord]
    findings: list[WatchFinding]
    interventions: list[InterventionPlan]
    integrity: dict[str, Any]


class OTelGenAISpan(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    trace_id: TraceId
    span_id: str = Field(pattern=r"^[a-fA-F0-9]{16,32}$")
    attributes: dict[str, str | int | float | bool] = Field(
        default_factory=dict, max_length=100
    )
    duration_ms: float | None = Field(default=None, ge=0, le=86_400_000)
    status: str = Field(default="ok", pattern=r"^(ok|error|unset)$")


class OTelGenAIIngestRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    spans: list[OTelGenAISpan] = Field(min_length=1, max_length=1000)


class OTelGenAIIngestResult(BaseModel):
    accepted: int
    rejected: int
    task_ids: list[TraceId]


class WatchFindingAction(BaseModel):
    status: str = Field(pattern=r"^(acknowledged|resolved|open)$")
    note: str = Field(default="", max_length=1000)


class WatchSummary(BaseModel):
    active_tasks: int
    open_findings: int
    high_risk_findings: int
    monitored_events: int
    estimated_cost_usd: float
    prevented_cost_usd: float = 0.0


class WatchProgress(BaseModel):
    task_id: TraceId
    tenant_id: str
    agent_id: str
    completed_milestones: list[str]
    missing_milestones: list[str]
    progress_score: float = Field(ge=0, le=1)
    last_progress_at: datetime | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)
    method: Literal["declared_milestones"] = "declared_milestones"


class ProductPlan(StrEnum):
    GATE_FREE = "gate_free"
    GATE = "gate"
    WATCH = "watch"
    WATCH_PLUS = "watch_plus"
    ENTERPRISE = "enterprise"


class TenantSubscription(BaseModel):
    tenant_id: str
    plan: ProductPlan
    status: str
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    extra_agents: int = 0
    current_period_end: datetime | None = None
    updated_at: datetime


class EntitlementSnapshot(BaseModel):
    tenant_id: str
    plan: ProductPlan
    subscription_status: str
    features: list[str]
    agent_limit: int | None
    decision_limit_monthly: int | None
    watch_event_limit_monthly: int | None
    llm_analysis_limit_monthly: int | None
    retention_days: int | None
    usage: dict[str, int]
    billing_attention: bool = False
    enforcement_enabled: bool = False


class BillingCheckoutRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    plan: ProductPlan
    extra_agents: int = Field(default=0, ge=0, le=10_000)
    customer_email: str | None = Field(default=None, max_length=320)


class BillingSessionResponse(BaseModel):
    url: str


class BillingPortalRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")


class OrganisationStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETION_PENDING = "deletion_pending"
    DELETED = "deleted"


class MembershipRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMINISTRATOR = "administrator"
    OWNER = "owner"


class OperatorAccount(BaseModel):
    subject: str
    email: str | None = None
    status: Literal["active", "suspended", "deleted"] = "active"
    created_at: datetime
    updated_at: datetime


class Organisation(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    name: str = Field(min_length=2, max_length=120)
    status: OrganisationStatus = OrganisationStatus.ACTIVE
    created_by: str
    created_at: datetime
    updated_at: datetime


class TenantMembership(BaseModel):
    tenant_id: str
    subject: str
    email: str | None = None
    role: MembershipRole
    status: Literal["active", "suspended"] = "active"
    created_at: datetime
    updated_at: datetime


class OrganisationCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    tenant_id: str | None = Field(
        default=None, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,127}$"
    )


class InvitationCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: MembershipRole
    expires_in_hours: int = Field(default=72, ge=1, le=168)


class TenantInvitation(BaseModel):
    id: str
    tenant_id: str
    email: str
    role: MembershipRole
    status: Literal["pending", "accepted", "revoked", "expired"]
    created_by: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None


class InvitationTokenResponse(BaseModel):
    invitation: TenantInvitation
    token: str


class InvitationAcceptRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class LegalAcceptanceRequest(BaseModel):
    terms_version: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,64}$")
    privacy_version: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,64}$")


class DeletionRequest(BaseModel):
    confirmation: str
    reason: str = Field(default="", max_length=1000)


class OperatorSession(BaseModel):
    id: str
    subject: str
    email: str | None = None
    csrf_token: str
    expires_at: datetime


class WatchIntelligenceRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    include_task_description: bool = False


class WatchIntelligenceResult(BaseModel):
    analysis_id: str
    task_id: TraceId
    tenant_id: str
    model: str
    prompt_version: str
    risk_found: bool
    category: str
    severity: str
    confidence: float = Field(ge=0, le=0.95)
    summary: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    recommended_action: str
    limitations: list[str] = Field(default_factory=list)
    finding_id: str | None = None
    created_at: datetime


class ResponsePolicyRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    finding_code: str = Field(pattern=r"^WATCH_[A-Z0-9_]{1,120}$")
    minimum_confidence: float = Field(default=0.99, ge=0.9, le=1.0)
    enabled: bool = False


class ResponsePolicy(BaseModel):
    tenant_id: str
    finding_code: str
    action: Literal["pause_task"] = "pause_task"
    minimum_confidence: float
    deterministic_only: bool = True
    enabled: bool
    updated_by: str
    updated_at: datetime


class TaskRecoveryRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    note: str = Field(min_length=1, max_length=1000)


class SessionRevocationRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    task_id: TraceId
    session_id: TraceId
    note: str = Field(min_length=1, max_length=1000)


class LineageRecord(BaseModel):
    id: str
    tenant_id: str
    agent_id: str
    trace_id: str
    request_id: str | None = None
    parent_ids: list[str] = Field(default_factory=list)
    source_type: str
    source_id: str
    destination: str
    trust: TrustLevel
    classification: DataClassification
    labels: list[TaintLabel] = Field(default_factory=list)
    content_digest: str
    created_at: datetime
    field_taint: dict[JsonPointer, FieldTaint] = Field(default_factory=dict)


class TraceSummary(BaseModel):
    tenant_id: str
    agent_id: str
    trace_id: TraceId
    trust: TrustLevel
    classification: DataClassification
    labels: list[TaintLabel]
    node_count: int
    last_seen: datetime


class ReleaseAgentRequest(BaseModel):
    reviewer: str = Field(default="", max_length=128, description="Deprecated")
    note: str = Field(default="", max_length=1000)


class MCPToolDefinition(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")
    description: str = Field(default="", max_length=20_000)
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)


class MCPManifestInspectionRequest(BaseModel):
    tools: list[MCPToolDefinition] = Field(min_length=1, max_length=500)
    accept_baseline: bool = False


class MCPToolFinding(BaseModel):
    code: str
    severity: str
    location: str
    detail: str


class MCPToolInspection(BaseModel):
    server_id: str
    tool_name: str
    digest: str
    baseline_digest: str | None = None
    status: str
    changed: bool = False
    findings: list[MCPToolFinding] = Field(default_factory=list)


class MCPManifestInspectionResult(BaseModel):
    server_id: str
    safe: bool
    accepted: bool
    inspected_at: datetime
    tools: list[MCPToolInspection]


class OnboardingPolicyRequest(BaseModel):
    agent_id: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")
    tools: list[dict[str, Any]] = Field(min_length=1, max_length=500)


class OnboardingSnippetRequest(BaseModel):
    framework: Literal["python", "openai-agents", "langgraph", "mcp"]
    tool_name: str = Field(
        default="search_knowledge", pattern=r"^[a-zA-Z0-9_.:-]{1,128}$"
    )
