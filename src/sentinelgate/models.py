from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, Field

TaintLabel = Annotated[
    str, Field(pattern=r"^[a-zA-Z0-9_.:-]{1,64}$", max_length=64)
]
JsonPointer = Annotated[str, Field(pattern=r"^(?:/(?:[^~/]|~[01])*)*$", max_length=1024)]
TraceId = Annotated[
    str, Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$", max_length=128)
]


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
    mcp_server_id: str | None = Field(
        default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,128}$"
    )


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
