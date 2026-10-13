import hashlib
from datetime import timedelta

import pytest

from sentinelgate.models import (
    AgentPrincipal,
    ToolCallRequest,
    WatchEventRequest,
    WatchEventType,
    WatchProfile,
    WatchTaskCreateRequest,
    utc_now,
)
from sentinelgate.service import GatewayService
from sentinelgate.watch import WatchService, WatchTaskNotFound


def watch_principal(principal: AgentPrincipal) -> AgentPrincipal:
    return principal.model_copy(
        update={"scopes": frozenset({*principal.scopes, "watch:write"})}
    )


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_watch_detects_repeated_calls_without_automatic_containment(store, principal):
    principal = watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="repeat-task",
            description="Check a deployment once",
            profile=WatchProfile.STRICT,
        ),
    )

    findings = []
    for _ in range(4):
        _, findings = watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.TOOL_CALL,
                tool_name="deployment_status",
                call_fingerprint=fingerprint("same-call"),
                outcome="allow",
            ),
        )

    assert "WATCH_REPEATED_CALL" in {item.code for item in findings}
    assert store.list_containments() == []


def test_watch_detects_retry_storm(store, principal):
    principal = watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="retry-task",
            description="Run a test",
            profile=WatchProfile.STRICT,
        ),
    )
    findings = []
    for _ in range(3):
        _, findings = watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.TOOL_RESULT,
                tool_name="run_tests",
                outcome="failed",
                error_code="ASSERTION_ERROR",
            ),
        )
    assert "WATCH_RETRY_STORM" in {item.code for item in findings}


def test_progress_signal_resets_repetition_detection(store, principal):
    principal = watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="progress-task",
            description="Process records in two phases",
            profile=WatchProfile.STRICT,
        ),
    )
    for _ in range(3):
        watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.TOOL_CALL,
                tool_name="process_batch",
                call_fingerprint=fingerprint("same-batch-shape"),
                outcome="allow",
            ),
        )
    watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            event_type=WatchEventType.PROGRESS,
            outcome="phase_one_complete",
        ),
    )
    _, findings = watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            event_type=WatchEventType.TOOL_CALL,
            tool_name="process_batch",
            call_fingerprint=fingerprint("same-batch-shape"),
            outcome="allow",
        ),
    )
    assert "WATCH_REPEATED_CALL" not in {item.code for item in findings}


def test_watch_detects_cyclic_workflow(store, principal):
    principal = watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="cycle-task",
            description="Resolve an issue",
            profile=WatchProfile.STRICT,
        ),
    )
    findings = []
    for value in ["a", "b", "a", "b", "a", "b"]:
        _, findings = watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.TOOL_CALL,
                tool_name=f"tool_{value}",
                call_fingerprint=fingerprint(value),
                outcome="allow",
            ),
        )
    assert "WATCH_CYCLIC_WORKFLOW" in {item.code for item in findings}


def test_watch_enforces_observational_cost_budget(store, principal):
    principal = watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="cost-task",
            description="Bounded research",
            max_cost_usd=0.01,
        ),
    )
    _, findings = watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            event_type=WatchEventType.TOOL_RESULT,
            tool_name="model_call",
            outcome="succeeded",
            estimated_cost_usd=0.011,
        ),
    )
    assert "WATCH_COST_BUDGET_EXCEEDED" in {item.code for item in findings}
    assert store.watch_summary().estimated_cost_usd == pytest.approx(0.011)


def test_watch_task_is_tenant_and_agent_bound(store, principal):
    principal = watch_principal(principal)
    watch = WatchService(store)
    watch.create_task(
        principal,
        WatchTaskCreateRequest(task_id="private-task", description="Private task"),
    )
    other = AgentPrincipal(
        agent_id="other-agent",
        tenant_id=principal.tenant_id,
        scopes=frozenset({"watch:write"}),
        token_id="other-token",
        expires_at=utc_now() + timedelta(hours=1),
    )
    with pytest.raises(WatchTaskNotFound):
        watch.ingest(
            other,
            WatchEventRequest(
                task_id="private-task",
                event_type=WatchEventType.HEARTBEAT,
            ),
        )


def test_gateway_automatically_feeds_watch(
    policy_file, store, signer, principal, service
):
    watch = WatchService(store)
    gateway = GatewayService(
        service.policy,
        store,
        service.provenance,
        service.executor,
        watch_service=watch,
    )
    for index in range(6):
        decision = gateway.evaluate(
            ToolCallRequest(
                request_id=f"watch-request-{index}",
                trace_id="watch-trace",
                task_id="watch-task",
                user_id="user",
                tool_name="search_knowledge",
                arguments={"query": "same query"},
                purpose="Find the security policy",
            ),
            principal,
        )
        assert decision.decision.value == "allow"

    findings = store.list_watch_findings(task_id="watch-task")
    assert "WATCH_REPEATED_CALL" in {item.code for item in findings}
    assert store.list_watch_tasks()[0].description == "Find the security policy"


def test_watch_failure_does_not_change_core_decision(service, principal, store):
    class BrokenWatch:
        def observe_gateway_call(self, *_args, **_kwargs):
            raise RuntimeError("simulated telemetry outage")

    service.watch_service = BrokenWatch()
    decision = service.evaluate(
        ToolCallRequest(
            user_id="user",
            tool_name="search_knowledge",
            arguments={"query": "security policy"},
        ),
        principal,
    )
    assert decision.decision.value == "allow"
    assert any(
        item["event_type"] == "watch_observation_failed"
        for item in store.recent_audit()
    )
