from datetime import datetime, timedelta

from sentinelgate.executor import ToolExecutionError, ToolRegistry, ToolValidationError
from sentinelgate.identity import TokenError
from sentinelgate.models import (
    AgentPrincipal,
    Decision,
    EnforcementMode,
    ExecutionResult,
    LineageRecord,
    PolicyDecision,
    PolicyReplayDecision,
    PolicyReplayRequest,
    PolicyReplayResult,
    SecurityFinding,
    SimulationRequest,
    ToolCallRequest,
    VerifiedProvenance,
    utc_now,
)
from sentinelgate.notifications import ApprovalNotifier
from sentinelgate.policy import Evaluation, PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.security import canonical_json, redact, request_hash, scan_secrets
from sentinelgate.storage import StorageIntegrityError, Store
from sentinelgate.taint import highest_classification, least_trusted


class GatewayService:
    def __init__(
        self,
        policy: PolicyEngine,
        store: Store,
        provenance: ProvenanceService,
        executor: ToolRegistry,
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
        approval_notifier: ApprovalNotifier | None = None,
    ):
        self.policy = policy
        self.store = store
        self.provenance = provenance
        self.executor = executor
        self.enforcement_mode = enforcement_mode
        self.approval_notifier = approval_notifier

    def available_tools(self, principal: AgentPrincipal) -> list[dict]:
        available = []
        definitions = {item["name"]: item for item in self.executor.definitions()}
        for name, definition in definitions.items():
            config = self.policy.tool_config(name)
            if not config or principal.agent_id not in config.get("allowed_agents", []):
                continue
            required = set(config.get("required_scopes", []))
            if required.issubset(principal.scopes):
                available.append(definition)
        return available

    def evaluate(
        self,
        call: ToolCallRequest,
        principal: AgentPrincipal,
        *,
        side_effects: bool = True,
    ) -> PolicyDecision:
        digest = request_hash(call, principal)
        findings = scan_secrets(call.arguments)
        operational_side_effects = (
            side_effects and self.enforcement_mode is not EnforcementMode.OBSERVE
        )
        containment = (
            self.store.active_containment(principal.tenant_id, principal.agent_id)
            if side_effects
            else None
        )
        if containment and containment.mode.value in {"quarantine", "revoke"}:
            result = Evaluation(
                Decision.DENY,
                ["AGENT_QUARANTINED", f"CONTAINMENT:{containment.mode.value.upper()}"],
                "critical", self.policy.version,
            )
            return self._finalize(
                call, principal, digest, result, findings, None, True, side_effects
            )
        if (
            containment
            and containment.mode.value == "restrict"
            and call.tool_name not in containment.allowed_tools
        ):
            result = Evaluation(
                Decision.DENY, ["CONTAINMENT:TOOL_RESTRICTED"],
                "high", self.policy.version,
            )
            return self._finalize(
                call, principal, digest, result, findings, None, False, side_effects
            )
        quarantined = side_effects and self.store.is_quarantined(
            principal.tenant_id, principal.agent_id
        )

        if quarantined:
            result = Evaluation(
                Decision.DENY, ["AGENT_QUARANTINED"], "critical", self.policy.version
            )
            return self._finalize(
                call, principal, digest, result, findings, None, True, side_effects
            )

        if operational_side_effects:
            limit = int(self.policy.defaults.get("requests_per_minute", 60))
            if not self.store.rate_allowed(
                principal.tenant_id, principal.agent_id, limit
            ):
                result = Evaluation(
                    Decision.DENY, ["RATE_LIMIT_EXCEEDED"], "high", self.policy.version
                )
                return self._finalize(
                    call, principal, digest, result, findings, None, False, side_effects
                )

        try:
            contexts = self._provenance_contexts(call, principal)
        except TokenError:
            result = Evaluation(
                Decision.DENY, ["INVALID_PROVENANCE"], "critical", self.policy.version
            )
            return self._finalize(
                call, principal, digest, result, findings, None, False, side_effects
            )

        result = self.policy.evaluate(call, principal, contexts, findings)
        result = self._apply_mcp_integrity(call, result)
        if result.decision is not Decision.DENY:
            try:
                self.executor.validate(call.tool_name, call.arguments)
            except ToolValidationError:
                result = Evaluation(
                    Decision.DENY,
                    ["INVALID_TOOL_ARGUMENTS"],
                    "high",
                    self.policy.version,
                )
        tool = self.policy.tool_config(call.tool_name) or {}
        if operational_side_effects and result.decision is not Decision.DENY and tool.get("egress", False):
            amount = len(canonical_json(call.arguments).encode("utf-8"))
            max_single = int(tool.get("max_egress_bytes", self.policy.defaults.get("max_egress_bytes", 100_000)))
            hourly = int(tool.get("hourly_egress_bytes", self.policy.defaults.get("hourly_egress_bytes", 1_000_000)))
            if amount > max_single:
                result = Evaluation(Decision.DENY, ["EGRESS_SINGLE_LIMIT_EXCEEDED"], "critical", self.policy.version)
            elif not self.store.egress_allowed(
                principal.tenant_id, principal.agent_id, amount, hourly
            ):
                result = Evaluation(Decision.DENY, ["EGRESS_HOURLY_BUDGET_EXCEEDED"], "critical", self.policy.version)
            elif self.store.trace_has_category(
                principal.tenant_id, principal.agent_id, call.trace_id, "sensitive_read"
            ):
                result = Evaluation(
                    Decision.REQUIRE_APPROVAL,
                    sorted({*result.reasons, "SUSPICIOUS_SEQUENCE:SENSITIVE_READ_TO_EGRESS"}),
                    "high", self.policy.version,
                )
        approval_id = None
        if result.decision is Decision.REQUIRE_APPROVAL and operational_side_effects:
            ttl = int(self.policy.defaults.get("approval_ttl_seconds", 900))
            approval = self.store.create_approval(call, digest, principal, ttl)
            approval_id = approval.id
            if self.approval_notifier and self.approval_notifier.enabled:
                delivered = self.approval_notifier.notify(approval, result.reasons)
                self.store.append_audit(
                    "approval_notification_delivered"
                    if delivered
                    else "approval_notification_failed",
                    {
                        "approval_id": approval.id,
                        "agent_id": principal.agent_id,
                        "tenant_id": principal.tenant_id,
                    },
                )

        if side_effects:
            snapshot_call = call.model_dump(mode="json")
            snapshot_call["provenance_tokens"] = []
            self.store.record_policy_snapshot(
                {
                    "tenant_id": principal.tenant_id,
                    "agent_id": principal.agent_id,
                    "scopes": sorted(principal.scopes),
                    "call": snapshot_call,
                    "provenance": [item.model_dump(mode="json") for item in contexts],
                    "findings": [item.model_dump(mode="json") for item in findings],
                    "original_decision": result.decision.value,
                    "created_at": utc_now().isoformat(),
                }
            )

        return self._finalize(
            call,
            principal,
            digest,
            result,
            findings,
            approval_id,
            False,
            side_effects,
        )

    def execute(
        self, call: ToolCallRequest, principal: AgentPrincipal
    ) -> ExecutionResult:
        decision = self.evaluate(call, principal)
        if self.enforcement_mode is EnforcementMode.OBSERVE:
            return ExecutionResult(
                request_id=call.request_id,
                status="observed_not_executed",
                decision=decision,
                trace_id=call.trace_id,
            )
        if decision.decision is Decision.DENY:
            return ExecutionResult(
                request_id=call.request_id,
                status=(
                    "warning_blocked"
                    if self.enforcement_mode is EnforcementMode.WARN
                    else "denied"
                ),
                decision=decision,
            )
        if decision.decision is Decision.REQUIRE_APPROVAL:
            return ExecutionResult(
                request_id=call.request_id,
                status="pending_approval",
                decision=decision,
                approval_id=decision.approval_id,
            )
        return self._execute_authorized(
            call, principal, decision.request_hash, decision
        )

    def execute_approved(self, approval_id: str) -> ExecutionResult | None:
        try:
            approval = self.store.get_approval(approval_id)
        except StorageIntegrityError:
            self.store.append_audit(
                "approval_integrity_failure", {"approval_id": approval_id}
            )
            return None
        if (
            not approval
            or approval.status != "approved"
            or approval.expires_at <= utc_now()
        ):
            return None
        principal = AgentPrincipal(
            agent_id=approval.agent_id,
            tenant_id=approval.tenant_id,
            scopes=frozenset(approval.scopes),
            token_id=f"approval:{approval.id}",
            expires_at=approval.expires_at,
        )
        if request_hash(approval.request, principal) != approval.request_hash:
            self.store.append_audit(
                "approval_integrity_failure", {"approval_id": approval.id}
            )
            return None
        if self.store.is_quarantined(principal.tenant_id, principal.agent_id):
            return ExecutionResult(
                request_id=approval.request.request_id, status="agent_quarantined"
            )

        findings = scan_secrets(approval.request.arguments)
        try:
            contexts = self._provenance_contexts(approval.request, principal)
        except TokenError:
            return ExecutionResult(
                request_id=approval.request.request_id,
                status="provenance_expired_or_invalid",
            )
        current = self.policy.evaluate(approval.request, principal, contexts, findings)
        current = self._apply_mcp_integrity(approval.request, current)
        if current.decision is Decision.DENY:
            self.store.append_audit(
                "approved_execution_blocked_by_current_policy",
                {"approval_id": approval.id, "reasons": current.reasons},
            )
            return ExecutionResult(
                request_id=approval.request.request_id,
                status="blocked_by_current_policy",
            )

        consumed = self.store.consume_approval(approval_id)
        if not consumed:
            return None
        return self._execute_authorized(
            approval.request, principal, approval.request_hash
        )

    def simulate(self, request: SimulationRequest) -> list[PolicyDecision]:
        principal = AgentPrincipal(
            agent_id=request.agent_id,
            tenant_id=request.tenant_id,
            scopes=frozenset(request.scopes),
            token_id="simulation",  # nosec B106
            expires_at=utc_now() + timedelta(hours=1),
        )
        return [
            self.evaluate(call, principal, side_effects=False) for call in request.calls
        ]

    def replay_policy(self, request: PolicyReplayRequest) -> PolicyReplayResult:
        engine = (
            PolicyEngine.from_mapping(request.policy)
            if request.policy is not None
            else self.policy
        )
        replayed: list[PolicyReplayDecision] = []
        counts = {item: 0 for item in Decision}
        for snapshot in self.store.list_policy_snapshots(request.limit):
            call = ToolCallRequest.model_validate(snapshot["call"])
            principal = AgentPrincipal(
                agent_id=snapshot["agent_id"],
                tenant_id=snapshot["tenant_id"],
                scopes=frozenset(snapshot["scopes"]),
                token_id="policy-replay",  # nosec B106
                expires_at=utc_now() + timedelta(minutes=5),
            )
            provenance = [
                VerifiedProvenance.model_validate(item)
                for item in snapshot["provenance"]
            ]
            findings = [
                SecurityFinding.model_validate(item) for item in snapshot["findings"]
            ]
            outcome = engine.evaluate(call, principal, provenance, findings)
            original = Decision(snapshot["original_decision"])
            counts[outcome.decision] += 1
            replayed.append(
                PolicyReplayDecision(
                    request_id=call.request_id,
                    trace_id=call.trace_id,
                    tool_name=call.tool_name,
                    original_decision=original,
                    replayed_decision=outcome.decision,
                    changed=outcome.decision is not original,
                    reason_codes=outcome.reasons,
                )
            )
        return PolicyReplayResult(
            policy_version=engine.version,
            evaluated=len(replayed),
            changed=sum(item.changed for item in replayed),
            allow=counts[Decision.ALLOW],
            deny=counts[Decision.DENY],
            require_approval=counts[Decision.REQUIRE_APPROVAL],
            decisions=replayed,
        )

    def _execute_authorized(
        self,
        call: ToolCallRequest,
        principal: AgentPrincipal,
        digest: str,
        decision: PolicyDecision | None = None,
    ) -> ExecutionResult:
        if not self.store.claim_execution(call.request_id, digest):
            self.store.append_audit(
                "execution_replay_blocked",
                {"request_id": call.request_id, "request_hash": digest},
            )
            return ExecutionResult(
                request_id=call.request_id, status="replay_blocked", decision=decision
            )
        tool = self.policy.tool_config(call.tool_name) or {}
        if tool.get("egress", False):
            amount = len(canonical_json(call.arguments).encode("utf-8"))
            hourly = int(
                tool.get(
                    "hourly_egress_bytes",
                    self.policy.defaults.get("hourly_egress_bytes", 1_000_000),
                )
            )
            if not self.store.reserve_egress(
                principal.tenant_id, principal.agent_id, amount, hourly
            ):
                self.store.finish_execution(call.request_id, "egress_budget_exceeded")
                self.store.append_audit(
                    "execution_egress_budget_blocked",
                    {
                        "request_id": call.request_id,
                        "agent_id": principal.agent_id,
                        "tenant_id": principal.tenant_id,
                        "bytes": amount,
                    },
                )
                return ExecutionResult(
                    request_id=call.request_id,
                    status="egress_budget_exceeded",
                    decision=decision,
                )
        try:
            result = self.executor.execute(call.tool_name, call.arguments)
            output_findings = scan_secrets(result.output)
            if output_findings:
                self.store.finish_execution(call.request_id, "output_blocked")
                self.store.append_audit(
                    "tool_output_blocked",
                    {
                        "request_id": call.request_id,
                        "request_hash": digest,
                        "findings": [item.model_dump() for item in output_findings],
                    },
                )
                return ExecutionResult(
                    request_id=call.request_id,
                    status="output_blocked",
                    decision=decision,
                )
            self.store.finish_execution(call.request_id, "succeeded")
            self.store.append_audit(
                "tool_executed",
                {
                    "request_id": call.request_id,
                    "request_hash": digest,
                    "agent_id": principal.agent_id,
                    "tenant_id": principal.tenant_id,
                    "tool_name": call.tool_name,
                        "output": redact(result.output),
                    },
                )
            parents = self._provenance_contexts(call, principal)
            attestation = self.provenance.derive_tool_output(
                tenant_id=principal.tenant_id,
                trace_id=call.trace_id,
                request_id=call.request_id,
                tool_name=call.tool_name,
                output=result.output,
                trust=result.trust,
                classification=result.classification,
                labels=set(result.labels),
                parents=parents,
            )
            self.store.record_lineage(
                LineageRecord(
                    id=attestation.lineage_id,
                    tenant_id=principal.tenant_id,
                    agent_id=principal.agent_id,
                    trace_id=call.trace_id,
                    request_id=call.request_id,
                    parent_ids=sorted(
                        {item.lineage_id for item in parents if item.lineage_id}
                    ),
                    source_type="tool_output",
                    source_id=",".join(result.sources) or f"tool:{call.tool_name}",
                    destination="agent_context",
                    trust=attestation.trust,
                    classification=attestation.classification,
                    labels=attestation.labels,
                    content_digest=attestation.content_digest,
                    created_at=utc_now(),
                )
            )
            return ExecutionResult(
                request_id=call.request_id,
                status="succeeded",
                decision=decision,
                output=result.output,
                output_provenance_token=attestation.token,
                classification=attestation.classification,
                taint_labels=attestation.labels,
                trace_id=call.trace_id,
            )
        except (ToolExecutionError, ToolValidationError) as exc:
            self.store.finish_execution(call.request_id, "failed")
            self.store.append_audit(
                "tool_execution_failed",
                {
                    "request_id": call.request_id,
                    "request_hash": digest,
                    "error": str(exc),
                },
            )
            return ExecutionResult(
                request_id=call.request_id, status="failed", decision=decision
            )

    def _provenance_contexts(
        self, call: ToolCallRequest, principal: AgentPrincipal
    ) -> list[VerifiedProvenance]:
        contexts = self.provenance.verify_many(
            call.provenance_tokens, principal.tenant_id
        )
        if any(item.trace_id and item.trace_id != call.trace_id for item in contexts):
            raise TokenError("Provenance trace mismatch")
        summary = self.store.trace_summary(
            principal.tenant_id, principal.agent_id, call.trace_id
        )
        if summary:
            contexts.append(
                VerifiedProvenance(
                    source_id=f"trace:{call.trace_id}",
                    content_digest="trace-aggregate",
                    trust=summary.trust,
                    signals=[],
                    classification=summary.classification,
                    labels=summary.labels,
                    trace_id=call.trace_id,
                )
            )
        window = int(self.policy.defaults.get("cross_trace_taint_window_seconds", 900))
        recent = self.store.recent_agent_lineage(
            principal.tenant_id, principal.agent_id, window
        )
        other_traces = [item for item in recent if item.trace_id != call.trace_id]
        if other_traces:
            contexts.append(
                VerifiedProvenance(
                    source_id=f"agent-window:{principal.agent_id}",
                    content_digest="agent-window-aggregate",
                    trust=least_trusted(item.trust for item in other_traces),
                    signals=[],
                    classification=highest_classification(
                        item.classification for item in other_traces
                    ),
                    labels=sorted(
                        {label for item in other_traces for label in item.labels}
                    ),
                )
            )
        return contexts

    def _apply_mcp_integrity(
        self, call: ToolCallRequest, result: Evaluation
    ) -> Evaluation:
        if result.decision is Decision.DENY:
            return result
        tool = self.policy.tool_config(call.tool_name) or {}
        expected_server = tool.get("mcp_server_id")
        if expected_server and call.mcp_server_id != expected_server:
            return Evaluation(
                Decision.DENY,
                ["MCP_SERVER_BINDING_REQUIRED"],
                "critical",
                self.policy.version,
            )
        if not call.mcp_server_id:
            return result
        manifest_name = str(tool.get("mcp_tool_name", call.tool_name))
        observation = self.store.get_mcp_tool_observation(
            call.mcp_server_id, manifest_name
        )
        if not observation:
            return Evaluation(
                Decision.DENY,
                ["MCP_TOOL_NOT_INSPECTED"],
                "critical",
                self.policy.version,
            )
        ttl = int(self.policy.defaults.get("mcp_observation_ttl_seconds", 3600))
        observed_at = datetime.fromisoformat(str(observation["observed_at"]))
        if observed_at < utc_now() - timedelta(seconds=ttl):
            return Evaluation(
                Decision.DENY,
                ["MCP_TOOL_INSPECTION_STALE"],
                "critical",
                self.policy.version,
            )
        status = str(observation["status"])
        reasons = [f"MCP_INTEGRITY:{status.upper()}"]
        reasons.extend(f"MCP_FINDING:{item}" for item in observation["findings"])
        if status == "blocked":
            return Evaluation(
                Decision.DENY, reasons, "critical", self.policy.version
            )
        if status == "review":
            return Evaluation(
                Decision.REQUIRE_APPROVAL,
                sorted({*result.reasons, *reasons}),
                "high",
                self.policy.version,
            )
        return result

    def _finalize(
        self,
        call: ToolCallRequest,
        principal: AgentPrincipal,
        digest: str,
        result: Evaluation,
        findings: list[SecurityFinding],
        approval_id: str | None,
        quarantined: bool,
        side_effects: bool,
    ) -> PolicyDecision:
        event_id = "simulation"
        became_quarantined = quarantined
        if side_effects:
            tool = self.policy.tool_config(call.tool_name) or {}
            category = str(tool.get("category", "other"))
            self.store.record_action(
                principal.tenant_id, principal.agent_id, call.trace_id,
                call.tool_name, category, result.decision.value,
            )
            if (
                self.enforcement_mode is not EnforcementMode.OBSERVE
                and
                result.decision is Decision.DENY
                and result.risk in {"high", "critical"}
                and "RATE_LIMIT_EXCEEDED" not in result.reasons
                and "AGENT_QUARANTINED" not in result.reasons
            ):
                window = int(self.policy.defaults.get("quarantine_window_seconds", 300))
                threshold = int(self.policy.defaults.get("quarantine_threshold", 5))
                count = self.store.record_violation(
                    principal.tenant_id,
                    principal.agent_id,
                    result.risk,
                    ",".join(result.reasons),
                    window,
                )
                self.store.upsert_incident(
                    principal.tenant_id,
                    principal.agent_id,
                    call.trace_id,
                    result.risk,
                    f"Blocked {call.tool_name}: {', '.join(result.reasons)}",
                )
                if count >= threshold:
                    self.store.quarantine(
                        principal.tenant_id,
                        principal.agent_id,
                        f"{count} high-risk denials in {window}s",
                    )
                    became_quarantined = True
            event_id = self.store.append_audit(
                "policy_decision",
                {
                    "request": redact(call.model_dump(mode="json")),
                    "request_hash": digest,
                    "agent_id": principal.agent_id,
                    "tenant_id": principal.tenant_id,
                    "decision": result.decision.value,
                    "reason_codes": result.reasons,
                    "risk": result.risk,
                    "policy_version": result.policy_version,
                    "security_findings": [item.model_dump() for item in findings],
                    "approval_id": approval_id,
                    "quarantined": became_quarantined,
                },
            )
        return PolicyDecision(
            request_id=call.request_id,
            request_hash=digest,
            agent_id=principal.agent_id,
            tenant_id=principal.tenant_id,
            decision=result.decision,
            reason_codes=result.reasons,
            risk=result.risk,
            policy_version=result.policy_version,
            security_findings=findings,
            approval_id=approval_id,
            audit_event_id=event_id,
            quarantined=became_quarantined,
            enforcement_mode=self.enforcement_mode,
            enforced=self.enforcement_mode is not EnforcementMode.OBSERVE,
        )
