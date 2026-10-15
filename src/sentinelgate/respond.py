"""Human-authorised, bounded response built from Watch evidence."""

from __future__ import annotations

import hashlib

from sentinelgate.models import (
    ContainmentMode,
    FlightRecorder,
    InterventionAction,
    InterventionPlan,
    WatchReplayRequest,
    WatchReplayResult,
    WatchReplayTaskResult,
)
from sentinelgate.security import canonical_json
from sentinelgate.storage import Store
from sentinelgate.watch import WatchService


class RespondError(ValueError):
    pass


class RespondService:
    def __init__(self, store: Store, watch: WatchService):
        self.store = store
        self.watch = watch

    def flight_recorder(
        self, task_id: str, tenant_id: str, agent_id: str | None = None
    ) -> FlightRecorder:
        task = self.store.get_watch_task(task_id, tenant_id, agent_id)
        if task is None:
            raise RespondError("Watch task not found")
        events = list(
            reversed(
                self.store.list_watch_events(
                    task_id, tenant_id, task.agent_id, limit=500
                )
            )
        )
        findings = self.store.list_watch_findings(
            limit=500, tenant_id=tenant_id, agent_id=task.agent_id, task_id=task_id
        )
        interventions = self.store.list_intervention_plans(
            limit=500, tenant_id=tenant_id, task_id=task_id
        )
        event_digest = hashlib.sha256(
            canonical_json([item.model_dump(mode="json") for item in events]).encode(
                "utf-8"
            )
        ).hexdigest()
        return FlightRecorder(
            task=task,
            events=events,
            findings=findings,
            interventions=interventions,
            integrity={
                "event_digest": event_digest,
                "event_count": len(events),
                "schema_versions": sorted({item.schema_version for item in events}),
                "audit_chain_valid": self.store.verify_audit_chain(),
                "arguments_stored": False,
            },
        )

    def replay(self, request: WatchReplayRequest) -> WatchReplayResult:
        tasks = self.store.list_watch_tasks(
            limit=request.limit, tenant_id=request.tenant_id
        )
        if request.task_ids:
            selected = set(request.task_ids)
            tasks = [task for task in tasks if task.task_id in selected]
        results: list[WatchReplayTaskResult] = []
        for task in tasks:
            current = {item.code for item in self.watch.analyze(task, persist=False)}
            candidate = {
                item.code
                for item in self.watch.analyze(
                    task, profile=request.candidate_profile, persist=False
                )
            }
            results.append(
                WatchReplayTaskResult(
                    task_id=task.task_id,
                    current_codes=sorted(current),
                    candidate_codes=sorted(candidate),
                    added_codes=sorted(candidate - current),
                    removed_codes=sorted(current - candidate),
                )
            )
        return WatchReplayResult(
            evaluated_tasks=len(results),
            changed_tasks=sum(
                bool(item.added_codes or item.removed_codes) for item in results
            ),
            candidate_profile=request.candidate_profile,
            added_findings=sum(len(item.added_codes) for item in results),
            removed_findings=sum(len(item.removed_codes) for item in results),
            results=results,
        )

    def decide_plan(
        self, plan_id: str, decision: str, reviewer: str, note: str
    ) -> InterventionPlan:
        status = "approved" if decision == "approve" else "rejected"
        plan = self.store.resolve_intervention_plan(plan_id, status, reviewer, note)
        if plan is None:
            raise RespondError("Intervention is missing or already resolved")
        self.store.append_audit(
            "intervention_plan_decided",
            {
                "plan_id": plan.id,
                "finding_id": plan.finding_id,
                "decision": decision,
                "reviewer": reviewer,
            },
        )
        return plan

    def execute_plan(self, plan_id: str, reviewer: str, note: str) -> InterventionPlan:
        plan = self.store.get_intervention_plan(plan_id)
        if plan is None or plan.status != "approved":
            raise RespondError("Intervention must be approved and unexecuted")
        plan = self.store.claim_intervention_execution(plan_id, reviewer)
        if plan is None:
            raise RespondError("Intervention was concurrently claimed")
        try:
            if plan.action is InterventionAction.PAUSE_TASK:
                if (
                    self.store.update_watch_task_status(
                        plan.tenant_id, plan.task_id, "paused"
                    )
                    is None
                ):
                    raise RespondError("Task is unavailable")
            elif plan.action in {
                InterventionAction.RESTRICT_AGENT,
                InterventionAction.QUARANTINE_AGENT,
            }:
                mode = (
                    ContainmentMode.RESTRICT
                    if plan.action is InterventionAction.RESTRICT_AGENT
                    else ContainmentMode.QUARANTINE
                )
                self.store.contain_agent(
                    tenant_id=plan.tenant_id,
                    agent_id=plan.agent_id,
                    mode=mode,
                    reason=f"Respond plan {plan.id}: {plan.rationale}",
                    reviewer=reviewer,
                    duration_seconds=int(plan.parameters.get("duration_seconds", 900)),
                    allowed_tools=list(plan.parameters.get("allowed_tools", [])),
                    incident_id=None,
                )
            elif plan.action is not InterventionAction.REVIEW_TASK:
                raise RespondError("Unsupported bounded intervention")
        except Exception as exc:
            self.store.fail_intervention_execution(
                plan.id, reviewer, f"{type(exc).__name__}: {exc}"
            )
            raise
        executed = self.store.mark_intervention_executed(plan.id, reviewer, note)
        if executed is None:
            raise RespondError("Intervention was concurrently resolved")
        self.store.append_audit(
            "intervention_plan_executed",
            {
                "plan_id": plan.id,
                "finding_id": plan.finding_id,
                "action": plan.action.value,
                "reviewer": reviewer,
            },
        )
        return executed

    def recover_task(self, tenant_id: str, task_id: str, reviewer: str, note: str):
        task = self.store.get_watch_task(task_id, tenant_id)
        if task is None:
            raise RespondError("Watch task not found")
        if task.status != "paused":
            raise RespondError("Only a paused task can be recovered")
        recovered = self.store.update_watch_task_status(tenant_id, task_id, "active")
        if recovered is None:
            raise RespondError("Task recovery failed")
        self.store.append_audit(
            "watch_task_recovered",
            {
                "tenant_id": tenant_id,
                "task_id": task_id,
                "reviewer": reviewer,
                "note": note,
            },
        )
        return recovered

    def revoke_session(
        self,
        tenant_id: str,
        task_id: str,
        session_id: str,
        reviewer: str,
        note: str,
    ) -> int:
        task = self.store.get_watch_task(task_id, tenant_id)
        if task is None:
            raise RespondError("Watch task not found")
        count = self.store.revoke_session_tokens(
            tenant_id,
            task_id,
            session_id,
            f"Session-level Watch+ revocation by {reviewer}: {note}",
        )
        if count == 0:
            raise RespondError("No active credential is bound to this task session")
        self.store.append_audit(
            "watch_session_credentials_revoked",
            {
                "tenant_id": tenant_id,
                "task_id": task_id,
                "session_id": session_id,
                "agent_id": task.agent_id,
                "reviewer": reviewer,
                "revoked_tokens": count,
                "note": note,
            },
        )
        return count
