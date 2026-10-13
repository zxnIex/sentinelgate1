"""Reproducible SentinelGate Watch Alpha regression simulator.

This exercises deterministic detector behavior. It is deliberately not presented
as an independent efficacy benchmark or evidence of novel-attack detection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelgate import __version__
from sentinelgate.models import (
    AgentPrincipal,
    WatchEventRequest,
    WatchEventType,
    WatchProfile,
    WatchTaskCreateRequest,
    utc_now,
)
from sentinelgate.storage import Store
from sentinelgate.watch import WatchService


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(task_id: str, kind: str, value: str = "") -> WatchEventRequest:
    if kind == "call":
        return WatchEventRequest(
            task_id=task_id,
            event_type=WatchEventType.TOOL_CALL,
            tool_name=value,
            outcome="allow",
            call_fingerprint=_fingerprint(value),
        )
    if kind == "error":
        return WatchEventRequest(
            task_id=task_id,
            event_type=WatchEventType.TOOL_RESULT,
            tool_name="connector_call",
            outcome="failed",
            error_code=value,
        )
    if kind == "progress":
        return WatchEventRequest(
            task_id=task_id,
            event_type=WatchEventType.PROGRESS,
            outcome=value,
            progress_signal=value,
        )
    raise ValueError(f"Unknown simulator event kind: {kind}")


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "stuck identical action",
        "expected": ["WATCH_REPEATED_CALL"],
        "events": [("call", "deployment_status")] * 4,
    },
    {
        "name": "connector retry storm",
        "expected": ["WATCH_RETRY_STORM"],
        "events": [("error", "UPSTREAM_TIMEOUT")] * 3,
    },
    {
        "name": "cyclic two-tool workflow",
        "expected": ["WATCH_CYCLIC_WORKFLOW"],
        "events": [("call", value) for value in ("search", "fetch") * 3],
    },
    {
        "name": "healthy phased batch",
        "expected": [],
        "events": [
            ("call", "fetch_page_1"),
            ("call", "fetch_page_2"),
            ("progress", "phase_one_complete"),
            ("call", "fetch_page_1"),
            ("progress", "phase_two_complete"),
        ],
    },
    {
        "name": "short legitimate workflow",
        "expected": [],
        "events": [
            ("call", "search_knowledge"),
            ("call", "read_document"),
            ("progress", "answer_ready"),
        ],
    },
]


def run() -> dict[str, object]:
    results: list[dict[str, object]] = []
    with TemporaryDirectory(prefix="sentinelgate-watch-") as directory:
        store = Store(
            Path(directory) / "watch.db",
            "watch-simulator-audit-key",
            "watch-simulator-encryption-key-32",
        )
        service = WatchService(store, monitor_only=True)
        principal = AgentPrincipal(
            agent_id="simulated-agent",
            tenant_id="watch-simulator",
            scopes=frozenset({"watch:write"}),
            token_id=hashlib.sha256(b"watch-simulator").hexdigest(),
            expires_at=utc_now() + timedelta(hours=1),
        )
        for index, scenario in enumerate(SCENARIOS):
            task_id = f"watch-scenario-{index}"
            service.create_task(
                principal,
                WatchTaskCreateRequest(
                    task_id=task_id,
                    description=str(scenario["name"]),
                    profile=WatchProfile.STRICT,
                ),
            )
            observed: set[str] = set()
            detection_event: dict[str, int] = {}
            for event_index, (kind, value) in enumerate(scenario["events"], start=1):
                _, findings = service.ingest(principal, _event(task_id, kind, value))
                for finding in findings:
                    observed.add(finding.code)
                    detection_event.setdefault(finding.code, event_index)
            expected = set(scenario["expected"])
            results.append(
                {
                    "name": scenario["name"],
                    "event_count": len(scenario["events"]),
                    "expected_findings": sorted(expected),
                    "observed_findings": sorted(observed),
                    "detection_event": detection_event,
                    "passed": observed == expected,
                }
            )

    attack_cases = [item for item in results if item["expected_findings"]]
    benign_cases = [item for item in results if not item["expected_findings"]]
    return {
        "suite": "sentinelgate-watch-alpha",
        "suite_version": "1.0.0",
        "sentinelgate_version": __version__,
        "claim_boundary": (
            "Project-authored deterministic regression simulator; not an efficacy "
            "claim, independent validation, or guarantee of semantic loop detection."
        ),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "scenario_count": len(results),
        "attack_scenarios_detected": sum(item["passed"] for item in attack_cases),
        "attack_scenario_count": len(attack_cases),
        "benign_scenarios_clear": sum(item["passed"] for item in benign_cases),
        "benign_scenario_count": len(benign_cases),
        "all_passed": all(item["passed"] for item in results),
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
