"""Run a reproducible 120-workflow Gate + Watch evaluation.

The suite exercises scripted tool calls through GatewayService and then observes
the same metadata path used by production Watch. It is project-authored evidence,
not independent validation or a claim about arbitrary semantic agent failures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelgate import __version__
from sentinelgate.executor import demo_registry
from sentinelgate.identity import TokenSigner
from sentinelgate.models import (
    AgentPrincipal,
    ToolCallRequest,
    WatchEventRequest,
    WatchEventType,
    WatchProfile,
    WatchTaskCreateRequest,
    utc_now,
)
from sentinelgate.policy import PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store
from sentinelgate.watch import WatchService

SUITE_VERSION = "1.1.0"
WORKFLOW_COUNT = 120
STEP_COST_USD = 0.001


@dataclass(frozen=True)
class Workflow:
    name: str
    kind: str
    abnormal: bool
    expected_codes: frozenset[str]
    partition: str


KINDS: tuple[tuple[str, bool, frozenset[str]], ...] = (
    ("identical_retry_loop", True, frozenset({"WATCH_REPEATED_CALL"})),
    ("connector_retry_storm", True, frozenset({"WATCH_RETRY_STORM"})),
    ("changing_argument_cycle", True, frozenset({"WATCH_NEAR_CYCLIC_WORKFLOW"})),
    ("undeclared_tool", True, frozenset({"WATCH_UNEXPECTED_TOOL"})),
    ("unexpected_second_session", True, frozenset({"WATCH_UNEXPECTED_MULTI_SESSION"})),
    ("reported_cost_overrun", True, frozenset({"WATCH_COST_BUDGET_EXCEEDED"})),
    ("activity_after_completion", True, frozenset({"WATCH_ACTIVITY_AFTER_COMPLETION"})),
    (
        "completion_without_milestones",
        True,
        frozenset({"WATCH_MISSING_SUCCESS_CRITERIA"}),
    ),
    ("legitimate_pagination", False, frozenset()),
    ("phased_long_running_task", False, frozenset()),
    ("intermittent_connector_failure", False, frozenset()),
    ("bounded_status_polling", False, frozenset()),
    ("late_but_valid_progress", False, frozenset()),
    ("short_task_without_progress_api", False, frozenset()),
    ("declared_multi_session_task", False, frozenset()),
    ("reported_cost_within_budget", False, frozenset()),
)


def workflows() -> list[Workflow]:
    items: list[Workflow] = []
    for index in range(WORKFLOW_COUNT):
        kind, abnormal, expected = KINDS[index % len(KINDS)]
        items.append(
            Workflow(
                name=f"{kind}-{index:03d}",
                kind=kind,
                abnormal=abnormal,
                expected_codes=expected,
                partition=(
                    "held_out"
                    if index % 4 == (index // len(KINDS)) % 4
                    else "development"
                ),
            )
        )
    return items


def _metrics(results: list[dict[str, object]]) -> dict[str, object]:
    tp = sum(
        bool(item["expected_abnormal"] and item["observed_abnormal"])
        for item in results
    )
    fp = sum(
        bool(not item["expected_abnormal"] and item["observed_abnormal"])
        for item in results
    )
    tn = sum(
        bool(not item["expected_abnormal"] and not item["observed_abnormal"])
        for item in results
    )
    fn = sum(
        bool(item["expected_abnormal"] and not item["observed_abnormal"])
        for item in results
    )
    delays = [
        int(item["detection_delay_events"])
        for item in results
        if item["detection_delay_events"] is not None
    ]
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "mean_detection_delay_events": sum(delays) / len(delays) if delays else None,
        "observed_waste_after_detection_usd": round(
            sum(float(item["observed_waste_after_detection_usd"]) for item in results),
            6,
        ),
        "projected_avoidable_waste_usd": round(
            sum(float(item["projected_avoidable_waste_usd"]) for item in results), 6
        ),
    }


def _call(
    gateway: GatewayService,
    watch: WatchService,
    principal: AgentPrincipal,
    task_id: str,
    tool_name: str,
    arguments: dict[str, object],
) -> None:
    call = ToolCallRequest(
        user_id="watch-evaluation",
        task_id=task_id,
        trace_id=task_id,
        tool_name=tool_name,
        arguments=arguments,
        purpose="Scripted Watch evaluation workflow",
    )
    decision = gateway.evaluate(call, principal, side_effects=False)
    watch.observe_gateway_call(call, principal, decision)


def _run_workflow(
    workflow: Workflow,
    gateway: GatewayService,
    watch: WatchService,
    store: Store,
    principal: AgentPrincipal,
) -> dict[str, object]:
    task_id = workflow.name
    expected_tools = ["search_knowledge"]
    success_criteria = (
        ["reviewed", "published"]
        if workflow.kind == "completion_without_milestones"
        else []
    )
    allow_multi_session = workflow.kind == "declared_multi_session_task"
    max_cost = 0.01 if workflow.kind == "reported_cost_overrun" else 0.05
    watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id=task_id,
            description=workflow.kind,
            profile=WatchProfile.STRICT,
            expected_tools=expected_tools,
            success_criteria=success_criteria,
            allow_multi_session=allow_multi_session,
            max_cost_usd=max_cost,
        ),
    )
    steps: list[tuple[str, dict[str, object]]] = []
    if workflow.kind == "identical_retry_loop":
        steps = [("call", {"tool": "search_knowledge", "query": "same"})] * 6
    elif workflow.kind == "connector_retry_storm":
        steps = [("error", {"code": "UPSTREAM_TIMEOUT"})] * 5
    elif workflow.kind == "changing_argument_cycle":
        steps = [
            ("call", {"tool": tool, "query": f"attempt-{index}"})
            for index, tool in enumerate(("search_knowledge", "unregistered_shell") * 3)
        ]
    elif workflow.kind == "undeclared_tool":
        steps = [("call", {"tool": "unregistered_shell", "query": "inspect"})]
    elif workflow.kind == "unexpected_second_session":
        steps = [("session", {"id": "session-a"}), ("session", {"id": "session-b"})]
    elif workflow.kind == "reported_cost_overrun":
        steps = [("cost", {"amount": 0.011})]
    elif workflow.kind == "activity_after_completion":
        steps = [
            ("terminal", {"outcome": "completed"}),
            ("session", {"id": "still-running"}),
        ]
    elif workflow.kind == "completion_without_milestones":
        steps = [
            ("progress", {"milestone": "reviewed"}),
            ("terminal", {"outcome": "completed"}),
        ]
    elif workflow.kind == "legitimate_pagination":
        steps = [
            ("call", {"tool": "search_knowledge", "query": f"page-{page}"})
            for page in range(8)
        ]
    elif workflow.kind == "phased_long_running_task":
        steps = [
            ("call", {"tool": "search_knowledge", "query": "batch"}),
            ("call", {"tool": "search_knowledge", "query": "batch"}),
            ("progress", {"milestone": "phase-one"}),
            ("call", {"tool": "search_knowledge", "query": "batch"}),
            ("call", {"tool": "search_knowledge", "query": "batch"}),
            ("progress", {"milestone": "phase-two"}),
        ]
    elif workflow.kind == "intermittent_connector_failure":
        steps = [
            ("call", {"tool": "search_knowledge", "query": "one"}),
            ("error", {"code": "TRANSIENT_TIMEOUT"}),
            ("call", {"tool": "search_knowledge", "query": "two"}),
            ("error", {"code": "TRANSIENT_TIMEOUT"}),
            ("progress", {"milestone": "recovered"}),
        ]
    elif workflow.kind == "bounded_status_polling":
        steps = [
            ("call", {"tool": "search_knowledge", "query": f"status-{item}"})
            for item in range(7)
        ]
    elif workflow.kind == "late_but_valid_progress":
        steps = [
            *[("call", {"tool": "search_knowledge", "query": "batch-a"})] * 3,
            ("progress", {"milestone": "phase-a"}),
            *[("call", {"tool": "search_knowledge", "query": "batch-b"})] * 3,
            ("progress", {"milestone": "phase-b"}),
        ]
    elif workflow.kind == "short_task_without_progress_api":
        steps = [
            ("call", {"tool": "search_knowledge", "query": f"short-{item}"})
            for item in range(3)
        ]
    elif workflow.kind == "declared_multi_session_task":
        steps = [("session", {"id": "worker-a"}), ("session", {"id": "worker-b"})]
    else:
        steps = [("cost", {"amount": 0.04})]

    detection_step: int | None = None
    observed_codes: set[str] = set()
    costs: list[float] = []
    for step_number, (kind, data) in enumerate(steps, start=1):
        if kind == "call":
            tool = str(data["tool"])
            arguments = {"query": str(data["query"])}
            _call(gateway, watch, principal, task_id, tool, arguments)
            costs.append(STEP_COST_USD)
        elif kind == "error":
            watch.ingest(
                principal,
                WatchEventRequest(
                    task_id=task_id,
                    event_type=WatchEventType.TOOL_RESULT,
                    tool_name="connector_call",
                    outcome="failed",
                    error_code=str(data["code"]),
                    estimated_cost_usd=STEP_COST_USD,
                ),
            )
            costs.append(STEP_COST_USD)
        elif kind == "session":
            watch.ingest(
                principal,
                WatchEventRequest(
                    task_id=task_id,
                    session_id=str(data["id"]),
                    event_type=WatchEventType.HEARTBEAT,
                ),
            )
            costs.append(0.0)
        elif kind == "terminal":
            watch.ingest(
                principal,
                WatchEventRequest(
                    task_id=task_id,
                    event_type=WatchEventType.TASK_STATUS,
                    outcome=str(data["outcome"]),
                ),
            )
            costs.append(0.0)
        elif kind == "cost":
            amount = float(data["amount"])
            watch.ingest(
                principal,
                WatchEventRequest(
                    task_id=task_id,
                    event_type=WatchEventType.TOOL_RESULT,
                    tool_name="model_call",
                    outcome="succeeded",
                    estimated_cost_usd=amount,
                ),
            )
            costs.append(amount)
        else:
            milestone = str(data["milestone"])
            watch.ingest(
                principal,
                WatchEventRequest(
                    task_id=task_id,
                    event_type=WatchEventType.PROGRESS,
                    progress_signal=milestone,
                    milestone_id=milestone,
                ),
            )
            costs.append(0.0)
        current = store.list_watch_findings(task_id=task_id)
        observed_codes.update(item.code for item in current)
        if current and detection_step is None:
            detection_step = step_number

    waste = sum(costs[detection_step:] if detection_step is not None else [])
    expected_start = 1 if workflow.abnormal else None
    return {
        "name": workflow.name,
        "kind": workflow.kind,
        "partition": workflow.partition,
        "expected_abnormal": workflow.abnormal,
        "observed_abnormal": bool(observed_codes),
        "expected_codes": sorted(workflow.expected_codes),
        "observed_codes": sorted(observed_codes),
        "missed_expected_codes": sorted(workflow.expected_codes - observed_codes),
        "unexpected_codes": sorted(observed_codes - workflow.expected_codes),
        "event_count": len(steps),
        "detection_event": detection_step,
        "detection_delay_events": (
            detection_step - expected_start
            if detection_step is not None and expected_start is not None
            else None
        ),
        "observed_waste_after_detection_usd": round(waste, 6),
        "projected_avoidable_waste_usd": round(waste, 6),
        "passed": bool(workflow.abnormal) == bool(observed_codes),
    }


def run(policy_path: Path, knowledge_path: Path) -> dict[str, object]:
    corpus = workflows()
    with TemporaryDirectory(prefix="sentinelgate-watch-evaluation-") as directory:
        store = Store(
            Path(directory) / "evaluation.db",
            "watch-evaluation-audit-key",
            "watch-evaluation-encryption-key-32",
        )
        signer = TokenSigner("watch-evaluation-token-key-32", "watch-evaluation")
        watch = WatchService(store, monitor_only=True)
        gateway = GatewayService(
            PolicyEngine(policy_path),
            store,
            ProvenanceService(signer),
            demo_registry(knowledge_path),
        )
        principal = AgentPrincipal(
            agent_id="research-agent",
            tenant_id="watch-evaluation",
            scopes=frozenset({"tools:search", "watch:write"}),
            token_id=hashlib.sha256(b"watch-evaluation").hexdigest(),
            expires_at=utc_now() + timedelta(hours=1),
        )
        results = [
            _run_workflow(item, gateway, watch, store, principal) for item in corpus
        ]
    development = [item for item in results if item["partition"] == "development"]
    held_out = [item for item in results if item["partition"] == "held_out"]
    return {
        "suite": "sentinelgate-watch-foundation",
        "suite_version": SUITE_VERSION,
        "sentinelgate_version": __version__,
        "claim_boundary": (
            "Project-authored scripted-agent evaluation. The held-out partition is "
            "excluded from threshold tuning but is not externally selected or validated."
        ),
        "counterfactual_model": (
            "Projected avoidable waste equals scheduled per-step cost after the first "
            "finding, assuming an immediate task pause. Observed waste is the cost the "
            "monitor-only run actually incurred after that finding."
        ),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "commit": os.getenv("SENTINELGATE_COMMIT")
            or os.getenv("GITHUB_SHA")
            or "unavailable",
        },
        "reproducibility": {
            "command": (
                "python -m sentinelgate.watch_evaluation "
                "--output evidence/watch-foundation-v0.15.json"
            ),
            "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "corpus_sha256": hashlib.sha256(
                json.dumps(
                    [
                        {
                            "name": item.name,
                            "kind": item.kind,
                            "abnormal": item.abnormal,
                            "expected_codes": sorted(item.expected_codes),
                            "partition": item.partition,
                        }
                        for item in corpus
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "workflow_families": sorted({item.kind for item in corpus}),
        },
        "workflow_count": len(results),
        "partitions": {
            "development": {"count": len(development), **_metrics(development)},
            "held_out": {"count": len(held_out), **_metrics(held_out)},
            "external": {
                "count": 0,
                "status": "awaiting_external_selection_and_validation",
                "results": [],
            },
            "combined": {"count": len(results), **_metrics(results)},
        },
        "failures": [item for item in results if not item["passed"]],
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("config/policies.json"))
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.policy, args.knowledge)
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if not result["failures"] else 1)


if __name__ == "__main__":
    main()
