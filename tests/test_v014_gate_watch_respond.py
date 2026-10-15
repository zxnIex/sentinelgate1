import hashlib
import sqlite3

import pytest
from pydantic import ValidationError

from sentinelgate.models import (
    ToolCallRequest,
    WatchEventRequest,
    WatchEventType,
    WatchProfile,
    WatchReplayRequest,
    WatchTaskCreateRequest,
)
from sentinelgate.respond import RespondError, RespondService
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store
from sentinelgate.watch import WatchService
from sentinelgate.watch_evaluation import workflows
from sentinelgate.worker import DurableWorker


def _principal(principal):
    return principal.model_copy(
        update={"scopes": frozenset({*principal.scopes, "watch:write"})}
    )


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_event_schema_rejects_unknown_versions():
    with pytest.raises(ValidationError):
        WatchEventRequest(
            schema_version="2.0",
            task_id="task",
            event_type=WatchEventType.HEARTBEAT,
        )
    schema = WatchEventRequest.model_json_schema()
    assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_task_context_drives_deterministic_findings(store, principal):
    principal = _principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="context-task",
            description="Publish after review",
            profile=WatchProfile.STRICT,
            expected_tools=["search_knowledge"],
            success_criteria=["reviewed", "published"],
        ),
    )
    _, findings = watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            session_id="session-a",
            event_type=WatchEventType.TOOL_CALL,
            tool_name="send_email",
            call_fingerprint=_fingerprint("unexpected"),
        ),
    )
    assert "WATCH_UNEXPECTED_TOOL" in {item.code for item in findings}
    watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            session_id="session-a",
            event_type=WatchEventType.PROGRESS,
            progress_signal="reviewed",
            milestone_id="reviewed",
        ),
    )
    _, findings = watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            session_id="session-a",
            event_type=WatchEventType.TASK_STATUS,
            outcome="completed",
        ),
    )
    assert "WATCH_MISSING_SUCCESS_CRITERIA" in {item.code for item in findings}


def test_multi_session_plan_requires_two_step_review_and_pauses_gate(
    store, principal, service
):
    principal = _principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(task_id="bounded-task", description="One runtime"),
    )
    for session in ("session-a", "session-b"):
        watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                session_id=session,
                event_type=WatchEventType.HEARTBEAT,
            ),
        )
    finding = next(
        item
        for item in store.list_watch_findings(task_id=task.task_id)
        if item.code == "WATCH_UNEXPECTED_MULTI_SESSION"
    )
    plan = store.list_intervention_plans(task_id=task.task_id)[0]
    assert plan.finding_id == finding.id
    assert plan.status == "proposed"
    respond = RespondService(store, watch)
    with pytest.raises(RespondError):
        respond.execute_plan(plan.id, "reviewer", "not approved")
    approved = respond.decide_plan(plan.id, "approve", "reviewer", "evidence checked")
    assert approved.status == "approved"
    executed = respond.execute_plan(plan.id, "reviewer", "pause only this task")
    assert executed.status == "executed"
    with pytest.raises(RespondError):
        respond.execute_plan(plan.id, "second-reviewer", "must not replay")

    gateway = GatewayService(
        service.policy,
        store,
        service.provenance,
        service.executor,
        watch_service=watch,
    )
    decision = gateway.evaluate(
        ToolCallRequest(
            user_id="user",
            task_id=task.task_id,
            tool_name="search_knowledge",
            arguments={"query": "security policy"},
        ),
        principal,
    )
    assert decision.decision.value == "deny"
    assert decision.reason_codes == ["WATCH:TASK_PAUSED"]


def test_flight_recorder_and_shadow_replay_are_side_effect_free(store, principal):
    principal = _principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="replay-task",
            description="Replay evidence",
            profile=WatchProfile.BALANCED,
        ),
    )
    for index in range(4):
        watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.TOOL_CALL,
                tool_name="search_knowledge",
                call_fingerprint=_fingerprint("same"),
                outcome="allow",
            ),
        )
    respond = RespondService(store, watch)
    before = len(store.list_watch_findings(task_id=task.task_id))
    result = respond.replay(WatchReplayRequest(candidate_profile=WatchProfile.STRICT))
    assert result.evaluated_tasks == 1
    assert result.added_findings >= 1
    assert len(store.list_watch_findings(task_id=task.task_id)) == before
    recorder = respond.flight_recorder(task.task_id, principal.tenant_id)
    assert recorder.integrity["event_count"] == 4
    assert recorder.integrity["schema_versions"] == ["1.0"]
    assert recorder.integrity["arguments_stored"] is False


def test_watch_beta_corpus_has_balanced_held_out_partition():
    items = workflows()
    held_out = [item for item in items if item.partition == "held_out"]
    assert len(items) == 120
    assert len(held_out) == 30
    assert any(item.abnormal for item in held_out)
    assert any(not item.abnormal for item in held_out)
    assert len({item.kind for item in held_out}) == 16


def test_high_risk_finding_uses_durable_outbox(store, principal):
    principal = _principal(principal)
    watch = WatchService(store, durable_notifications=True)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="notified-task",
            description="Unexpected tool",
            expected_tools=["search_knowledge"],
        ),
    )
    watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            event_type=WatchEventType.TOOL_CALL,
            tool_name="send_email",
            call_fingerprint=_fingerprint("send-email"),
        ),
    )
    jobs = store.list_outbox()
    assert jobs[0]["kind"] == "watch.finding"

    class Notifier:
        def notify_finding(self, finding):
            return finding.code == "WATCH_UNEXPECTED_TOOL"

    result = DurableWorker(store, Notifier(), "watch-worker").process_one()
    assert result.completed is True
    assert store.list_outbox()[0]["status"] == "completed"


def test_multi_agent_workflow_uses_distinct_agent_owned_tasks(store, principal):
    first = _principal(principal)
    second = first.model_copy(update={"agent_id": "research-agent-2"})
    watch = WatchService(store)
    watch.create_task(
        first,
        WatchTaskCreateRequest(
            task_id="workflow-child-a",
            workflow_id="shared-workflow",
            description="Research",
        ),
    )
    watch.create_task(
        second,
        WatchTaskCreateRequest(
            task_id="workflow-child-b",
            workflow_id="shared-workflow",
            description="Review",
        ),
    )
    tasks = store.list_watch_tasks(workflow_id="shared-workflow")
    assert {item.agent_id for item in tasks} == {
        "research-agent",
        "research-agent-2",
    }


def test_v011_sqlite_watch_schema_migrates_in_place(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.executescript(
            """
            CREATE TABLE watch_tasks (
                task_id TEXT NOT NULL, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                description TEXT NOT NULL, profile TEXT NOT NULL,
                expected_tools_json TEXT NOT NULL, success_criteria_json TEXT NOT NULL,
                max_runtime_seconds INTEGER NOT NULL, max_tool_calls INTEGER NOT NULL,
                max_cost_usd REAL NOT NULL, status TEXT NOT NULL,
                event_count INTEGER NOT NULL, estimated_cost_usd REAL NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT,
                PRIMARY KEY(tenant_id, task_id)
            );
            CREATE TABLE watch_events (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL, event_type TEXT NOT NULL, tool_name TEXT,
                outcome TEXT, error_code TEXT, call_fingerprint TEXT,
                progress_signal TEXT, input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL, estimated_cost_usd REAL NOT NULL,
                duration_ms REAL, created_at TEXT NOT NULL
            );
            """
        )
    migrated = Store(path, "audit-key", "encryption-key-at-least-24")
    with sqlite3.connect(path) as db:
        task_columns = {row[1] for row in db.execute("PRAGMA table_info(watch_tasks)")}
        event_columns = {
            row[1] for row in db.execute("PRAGMA table_info(watch_events)")
        }
    assert {"workflow_id", "allow_multi_session"}.issubset(task_columns)
    assert {"schema_version", "session_id", "milestone_id"}.issubset(event_columns)
    assert migrated.backend == "sqlite"
