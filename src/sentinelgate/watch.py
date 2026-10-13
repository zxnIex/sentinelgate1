"""Deterministic, explainable runtime monitoring for SentinelGate Watch."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sentinelgate.models import (
    AgentPrincipal,
    PolicyDecision,
    ToolCallRequest,
    WatchEventRecord,
    WatchEventRequest,
    WatchEventType,
    WatchFinding,
    WatchProfile,
    WatchTaskCreateRequest,
    WatchTaskRecord,
    utc_now,
)
from sentinelgate.security import canonical_json
from sentinelgate.storage import Store


@dataclass(frozen=True)
class WatchThresholds:
    repeated_calls: int
    repeated_errors: int
    repeated_denials: int
    poll_calls: int
    cycle_repetitions: int
    no_progress_seconds: int
    window_seconds: int = 300


PROFILES = {
    WatchProfile.RELAXED: WatchThresholds(10, 8, 6, 20, 4, 1800),
    WatchProfile.BALANCED: WatchThresholds(6, 5, 4, 12, 3, 900),
    WatchProfile.STRICT: WatchThresholds(4, 3, 3, 8, 3, 600),
}


class WatchTaskNotFound(ValueError):
    pass


class WatchService:
    """Consumes metadata-only events and emits evidence-backed findings.

    Watch never executes tools or applies containment. Its response boundary is
    deliberately advisory; authenticated SentinelGate Core endpoints remain the
    only path to pause, restrict, quarantine, or revoke an agent.
    """

    def __init__(self, store: Store, enabled: bool = True, monitor_only: bool = True):
        self.store = store
        self.enabled = enabled
        self.monitor_only = monitor_only

    def create_task(
        self, principal: AgentPrincipal, request: WatchTaskCreateRequest
    ) -> WatchTaskRecord:
        record = self.store.create_watch_task(principal, request)
        self.store.append_audit(
            "watch_task_created",
            {
                "task_id": record.task_id,
                "tenant_id": record.tenant_id,
                "agent_id": record.agent_id,
                "profile": record.profile.value,
            },
        )
        return record

    def ingest(
        self, principal: AgentPrincipal, request: WatchEventRequest
    ) -> tuple[WatchEventRecord, list[WatchFinding]]:
        if not self.enabled:
            raise ValueError("SentinelGate Watch is disabled")
        task = self.store.get_watch_task(
            request.task_id, principal.tenant_id, principal.agent_id
        )
        if task is None:
            raise WatchTaskNotFound("Watch task not found for this agent identity")
        event = self.store.record_watch_event(principal, request)
        updated = self.store.get_watch_task(
            request.task_id, principal.tenant_id, principal.agent_id
        )
        findings = self.analyze(updated or task, now=event.created_at)
        return event, findings

    def observe_gateway_call(
        self,
        call: ToolCallRequest,
        principal: AgentPrincipal,
        decision: PolicyDecision,
    ) -> list[WatchFinding]:
        if not self.enabled:
            return []
        task_id = call.task_id or call.trace_id
        task = self.store.get_watch_task(task_id, principal.tenant_id, principal.agent_id)
        if task is None:
            task = self.store.create_watch_task(
                principal,
                WatchTaskCreateRequest(
                    task_id=task_id,
                    description=call.purpose or f"Gateway trace {call.trace_id}",
                    profile=WatchProfile.BALANCED,
                ),
                audit=False,
            )
        fingerprint = self.store.metadata_fingerprint(
            f"{call.tool_name}\0{canonical_json(call.arguments)}"
        )
        self.store.record_watch_event(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.TOOL_CALL,
                tool_name=call.tool_name,
                outcome=decision.decision.value,
                error_code=(
                    decision.reason_codes[0]
                    if decision.decision.value == "deny" and decision.reason_codes
                    else None
                ),
                call_fingerprint=fingerprint,
            ),
        )
        updated = self.store.get_watch_task(
            task.task_id, principal.tenant_id, principal.agent_id
        )
        return self.analyze(updated or task)

    def observe_execution(
        self,
        call: ToolCallRequest,
        principal: AgentPrincipal,
        outcome: str,
        duration_ms: float,
        error_code: str | None = None,
    ) -> list[WatchFinding]:
        if not self.enabled:
            return []
        task_id = call.task_id or call.trace_id
        task = self.store.get_watch_task(task_id, principal.tenant_id, principal.agent_id)
        if task is None:
            return []
        self.store.record_watch_event(
            principal,
            WatchEventRequest(
                task_id=task_id,
                event_type=WatchEventType.TOOL_RESULT,
                tool_name=call.tool_name,
                outcome=outcome,
                error_code=error_code,
                duration_ms=duration_ms,
            ),
        )
        updated = self.store.get_watch_task(
            task.task_id, principal.tenant_id, principal.agent_id
        )
        return self.analyze(updated or task)

    def analyze(
        self, task: WatchTaskRecord, *, now: datetime | None = None
    ) -> list[WatchFinding]:
        now = now or utc_now()
        thresholds = PROFILES[task.profile]
        events = self.store.list_watch_events(
            task.task_id,
            tenant_id=task.tenant_id,
            agent_id=task.agent_id,
            limit=500,
        )
        window = [
            item
            for item in events
            if item.created_at >= now - timedelta(seconds=thresholds.window_seconds)
        ]
        findings: list[WatchFinding] = []

        progress_in_window = [
            item for item in window if item.event_type is WatchEventType.PROGRESS
        ]
        last_window_progress = max(
            (item.created_at for item in progress_in_window), default=None
        )
        calls = [item for item in window if item.event_type is WatchEventType.TOOL_CALL]
        # Explicit progress is a phase boundary. A healthy long-running task can
        # legitimately make the same call in separate phases, so loop detection
        # only considers calls made since the most recent milestone.
        loop_calls = [
            item
            for item in calls
            if last_window_progress is None or item.created_at > last_window_progress
        ]
        fingerprints = [
            item.call_fingerprint for item in loop_calls if item.call_fingerprint
        ]
        most_common_call = self._most_common(fingerprints)
        if most_common_call and most_common_call[1] >= thresholds.repeated_calls:
            findings.append(
                self._finding(
                    task,
                    "WATCH_REPEATED_CALL",
                    "medium",
                    0.98,
                    "The same tool call repeated without a progress signal.",
                    [f"fingerprint={most_common_call[0][:12]}", f"count={most_common_call[1]}", f"window={thresholds.window_seconds}s"],
                    "Review the task and pause it if the repeated call is not expected.",
                )
            )

        errors = [item.error_code for item in window if item.error_code]
        most_common_error = self._most_common(errors)
        if most_common_error and most_common_error[1] >= thresholds.repeated_errors:
            findings.append(
                self._finding(
                    task,
                    "WATCH_RETRY_STORM",
                    "high",
                    0.99,
                    "The same failure is recurring beyond the configured retry tolerance.",
                    [f"error={most_common_error[0]}", f"count={most_common_error[1]}"],
                    "Require human review before additional retries.",
                )
            )

        denied = [item for item in calls if item.outcome == "deny"]
        if len(denied) >= thresholds.repeated_denials:
            findings.append(
                self._finding(
                    task,
                    "WATCH_REPEATED_DENIAL",
                    "high",
                    0.99,
                    "The agent continues attempting actions SentinelGate Core denied.",
                    [f"denied_calls={len(denied)}", f"window={thresholds.window_seconds}s"],
                    "Inspect the policy mismatch and consider restricting the agent session.",
                )
            )

        polling = [item for item in calls if self._looks_like_poll(item.tool_name)]
        if len(polling) >= thresholds.poll_calls:
            findings.append(
                self._finding(
                    task,
                    "WATCH_EXCESSIVE_POLLING",
                    "medium",
                    0.95,
                    "The task is polling status-like tools unusually frequently.",
                    [f"poll_calls={len(polling)}", f"window={thresholds.window_seconds}s"],
                    "Increase the polling interval or use an event-driven callback.",
                )
            )

        ordered = list(
            reversed([item for item in loop_calls if item.call_fingerprint])
        )
        cycle = self._cycle_pattern(
            [item.call_fingerprint or "" for item in ordered],
            thresholds.cycle_repetitions,
        )
        if cycle:
            findings.append(
                self._finding(
                    task,
                    "WATCH_CYCLIC_WORKFLOW",
                    "high",
                    0.96,
                    "The task is cycling through the same sequence of tool calls.",
                    [f"cycle_length={len(cycle)}", f"repetitions={thresholds.cycle_repetitions}"],
                    "Pause and change strategy before continuing the workflow.",
                )
            )

        all_calls = [item for item in events if item.event_type is WatchEventType.TOOL_CALL]
        if len(all_calls) > task.max_tool_calls:
            findings.append(
                self._finding(
                    task,
                    "WATCH_TOOL_BUDGET_EXCEEDED",
                    "high",
                    1.0,
                    "The task exceeded its configured event budget.",
                    [f"tool_calls={len(all_calls)}", f"budget={task.max_tool_calls}"],
                    "Require review before extending the task budget.",
                )
            )
        if task.estimated_cost_usd > task.max_cost_usd:
            findings.append(
                self._finding(
                    task,
                    "WATCH_COST_BUDGET_EXCEEDED",
                    "high",
                    1.0,
                    "The task exceeded its configured estimated-cost budget.",
                    [f"estimated_cost_usd={task.estimated_cost_usd:.6f}", f"budget_usd={task.max_cost_usd:.6f}"],
                    "Require review before allowing additional paid inference or tools.",
                )
            )
        runtime = (now - task.created_at).total_seconds()
        if runtime > task.max_runtime_seconds and task.status == "active":
            findings.append(
                self._finding(
                    task,
                    "WATCH_RUNTIME_BUDGET_EXCEEDED",
                    "high",
                    1.0,
                    "The task exceeded its configured runtime budget.",
                    [f"runtime_seconds={int(runtime)}", f"budget_seconds={task.max_runtime_seconds}"],
                    "Review or pause the long-running task.",
                )
            )

        progress = [item for item in events if item.event_type is WatchEventType.PROGRESS]
        last_progress_at = max((item.created_at for item in progress), default=task.created_at)
        meaningful_events = [item for item in events if item.event_type is not WatchEventType.HEARTBEAT]
        if (
            meaningful_events
            and task.status == "active"
            and (now - last_progress_at).total_seconds() > thresholds.no_progress_seconds
        ):
            findings.append(
                self._finding(
                    task,
                    "WATCH_NO_PROGRESS",
                    "medium",
                    0.85,
                    "The task has emitted activity but no explicit progress signal.",
                    [f"seconds_since_progress={int((now - last_progress_at).total_seconds())}"],
                    "Ask the runtime to report a milestone or request human review.",
                )
            )

        persisted = [self.store.upsert_watch_finding(item) for item in findings]
        for finding in persisted:
            self.store.append_audit(
                "watch_finding_observed",
                {
                    "finding_id": finding.id,
                    "task_id": finding.task_id,
                    "tenant_id": finding.tenant_id,
                    "agent_id": finding.agent_id,
                    "code": finding.code,
                    "severity": finding.severity,
                    "monitor_only": self.monitor_only,
                },
            )
        return persisted

    @staticmethod
    def _most_common(values: Iterable[str]) -> tuple[str, int] | None:
        counts: dict[str, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        return max(counts.items(), key=lambda item: item[1]) if counts else None

    @staticmethod
    def _looks_like_poll(tool_name: str | None) -> bool:
        value = (tool_name or "").casefold()
        return any(token in value for token in ("poll", "status", "check_job", "wait"))

    @staticmethod
    def _cycle_pattern(values: list[str], repetitions: int) -> list[str]:
        for length in range(2, min(6, len(values) // repetitions) + 1):
            tail = values[-length * repetitions :]
            pattern = tail[:length]
            if pattern * repetitions == tail and len(set(pattern)) > 1:
                return pattern
        return []

    @staticmethod
    def _finding(
        task: WatchTaskRecord,
        code: str,
        severity: str,
        confidence: float,
        summary: str,
        evidence: list[str],
        recommended_action: str,
    ) -> WatchFinding:
        now = utc_now()
        finding_id = hashlib.sha256(
            f"{task.tenant_id}\0{task.task_id}\0{code}".encode()
        ).hexdigest()
        return WatchFinding(
            id=finding_id,
            tenant_id=task.tenant_id,
            agent_id=task.agent_id,
            task_id=task.task_id,
            code=code,
            severity=severity,
            confidence=confidence,
            summary=summary,
            evidence=evidence,
            recommended_action=recommended_action,
            status="open",
            occurrences=1,
            first_seen=now,
            last_seen=now,
        )
