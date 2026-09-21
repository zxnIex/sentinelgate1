"""End-to-end HTTP load benchmark for an isolated SentinelGate deployment."""

import argparse
import asyncio
import json
import os
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import psutil

from sentinelgate.benchmark import percentile
from sentinelgate.executor import demo_registry


def _latency_summary(samples: list[float]) -> dict[str, float]:
    return {
        "p50": round(percentile(samples, 0.50), 3),
        "p95": round(percentile(samples, 0.95), 3),
        "p99": round(percentile(samples, 0.99), 3),
        "mean": round(statistics.fmean(samples), 3),
    }


async def _issue_token(client: httpx.AsyncClient, admin_token: str) -> str:
    response = await client.post(
        "/v1/tokens/agents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "agent_id": "research-agent",
            "tenant_id": f"benchmark-{uuid4().hex[:12]}",
            "scopes": ["tools:search", "tools:email:send", "provenance:attest", "provenance:attest:trusted"],
            "ttl_seconds": 86400,
            "owner": "benchmark",
        },
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


async def _attest(
    client: httpx.AsyncClient, token: str, value: dict[str, str], trust: str, label: str | None = None
) -> tuple[str, str]:
    trace_id = f"bench-attest-{uuid4().hex}"
    payload: dict[str, Any] = {
        "source_id": f"benchmark:{uuid4()}", "value": value,
        "trust": trust, "classification": "public", "labels": [],
        "trace_id": trace_id,
    }
    if label:
        payload["labels"] = [label]
    response = await client.post(
        "/v1/provenance/attest-structured",
        headers={"Authorization": f"Bearer {token}"}, json=payload,
    )
    response.raise_for_status()
    return str(response.json()["token"]), trace_id


def _call(
    index: int,
    trusted_token: str,
    trusted_trace: str,
    untrusted_token: str,
    untrusted_trace: str,
) -> tuple[str, dict[str, Any]]:
    scenario = index % 5
    common = {"request_id": str(uuid4()), "user_id": "benchmark", "trace_id": f"load-{uuid4().hex}"}
    if scenario == 0:
        return "safe", {**common, "tool_name": "search_knowledge", "arguments": {"query": "security policy"}}
    if scenario == 1:
        return "denied", {**common, "tool_name": "unknown_tool", "arguments": {}}
    if scenario == 2:
        value = {"body": "Reviewed benchmark summary"}
        return "approval", {
            **common, "trace_id": trusted_trace, "tool_name": "send_email",
            "arguments": {"to": "security@example.com", "subject": "Benchmark", **value},
            "field_provenance": {"/body": [{"token": trusted_token, "source_pointer": "/body"}]},
        }
    if scenario == 3:
        value = {"body": "External instruction"}
        return "field_tainted", {
            **common, "trace_id": untrusted_trace, "tool_name": "send_email",
            "arguments": {"to": "security@example.com", "subject": "Benchmark", **value},
            "field_provenance": {"/body": [{"token": untrusted_token, "source_pointer": "/body"}]},
        }
    sizes = (1024, 10_240, 102_400, 1_048_576)
    return "payload", {
        **common, "tool_name": "unknown_tool",
        "arguments": {"payload": "x" * sizes[(index // 5) % len(sizes)]},
    }


async def _resource_monitor(pid: int | None, stop: asyncio.Event) -> dict[str, float | None]:
    process = psutil.Process(pid) if pid else psutil.Process()
    peak_rss = process.memory_info().rss
    cpu_start = sum(process.cpu_times()[:2])
    while not stop.is_set():
        try:
            peak_rss = max(peak_rss, process.memory_info().rss)
        except psutil.Error:
            break
        await asyncio.sleep(0.05)
    try:
        cpu_end = sum(process.cpu_times()[:2])
    except psutil.Error:
        cpu_end = cpu_start
    return {"pid": pid or os.getpid(), "peak_rss_mb": round(peak_rss / 1_048_576, 2), "cpu_seconds": round(cpu_end - cpu_start, 3)}


async def _level(
    client: httpx.AsyncClient, tokens: dict[str, str], trusted: tuple[str, str],
    untrusted: tuple[str, str],
    concurrency: int, requests: int, server_pid: int | None, endpoint: str,
) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(concurrency)
    samples: list[float] = []
    statuses: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    by_scenario: dict[str, list[float]] = defaultdict(list)
    stop = asyncio.Event()
    monitor = asyncio.create_task(_resource_monitor(server_pid, stop))

    async def one(index: int) -> None:
        scenario, payload = _call(index, trusted[0], trusted[1], untrusted[0], untrusted[1])
        async with semaphore:
            before = time.perf_counter()
            try:
                response = await client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {tokens[scenario]}"},
                    json=payload,
                )
                elapsed = (time.perf_counter() - before) * 1000
                statuses[str(response.status_code)] += 1
                if response.headers.get("content-type", "").startswith("application/json"):
                    body = response.json()
                    decision = body.get("decision", "none")
                    if isinstance(decision, dict):
                        decision = decision.get("decision", "none")
                    decisions[str(decision)] += 1
            except (httpx.HTTPError, ValueError) as exc:
                elapsed = (time.perf_counter() - before) * 1000
                statuses[f"exception:{type(exc).__name__}"] += 1
            samples.append(elapsed)
            by_scenario[scenario].append(elapsed)

    started = time.perf_counter()
    await asyncio.gather(*(one(index) for index in range(requests)))
    elapsed = time.perf_counter() - started
    stop.set()
    resources = await monitor
    return {
        "concurrency": concurrency,
        "requests": requests,
        "elapsed_seconds": round(elapsed, 3),
        "throughput_rps": round(requests / elapsed, 2),
        "latency_ms": _latency_summary(samples),
        "scenario_latency_ms": {name: _latency_summary(values) for name, values in by_scenario.items()},
        "http_statuses": dict(statuses),
        "decisions": dict(decisions),
        "error_rate": round(sum(count for key, count in statuses.items() if key != "200") / requests, 6),
        "resources": resources,
    }


def _direct_baseline(iterations: int, knowledge_path: Path) -> dict[str, Any]:
    registry = demo_registry(knowledge_path)
    samples = []
    before_all = time.perf_counter()
    for _ in range(iterations):
        before = time.perf_counter()
        registry.execute("search_knowledge", {"query": "security policy"})
        samples.append((time.perf_counter() - before) * 1000)
    elapsed = time.perf_counter() - before_all
    return {"iterations": iterations, "latency_ms": _latency_summary(samples), "throughput_rps": round(iterations / elapsed, 2)}


async def run(
    base_url: str, admin_token: str, concurrency: list[int], requests: int,
    server_pid: int | None = None, endpoint: str = "/v1/execute",
) -> dict[str, Any]:
    timeout = httpx.Timeout(60.0)
    limits = httpx.Limits(max_connections=max(concurrency) + 20, max_keepalive_connections=max(concurrency) + 20)
    async with httpx.AsyncClient(
        base_url=base_url.rstrip("/"), timeout=timeout, limits=limits, trust_env=False
    ) as client:
        health_response = await client.get("/health")
        health_response.raise_for_status()
        readiness_response = await client.get("/ready")
        readiness_response.raise_for_status()
        levels = []
        for level in concurrency:
            # Isolate rate limits, taint and containment between scenario classes.
            tokens = {
                scenario: await _issue_token(client, admin_token)
                for scenario in ("safe", "denied", "approval", "field_tainted", "payload")
            }
            trusted = await _attest(
                client,
                tokens["approval"],
                {"body": "Reviewed benchmark summary"},
                "trusted",
            )
            untrusted = await _attest(
                client,
                tokens["field_tainted"],
                {"body": "External instruction"},
                "untrusted",
                "external",
            )
            levels.append(
                await _level(
                    client, tokens, trusted, untrusted, level, requests, server_pid,
                    endpoint,
                )
            )
    root = Path(__file__).resolve().parents[2]
    return {
        "benchmark": "sentinelgate_end_to_end_http",
        "base_url": base_url,
        "transport": "TLS included" if base_url.startswith("https://") else "plaintext HTTP",
        "endpoint": endpoint,
        "server": {
            "health": health_response.json(),
            "readiness": readiness_response.json(),
        },
        "direct_tool_baseline": _direct_baseline(min(requests, 10_000), root / "knowledge"),
        "levels": levels,
        "total_requests": requests * len(concurrency),
        "limitations": [
            (
                "Client-observed latency includes HTTP, authentication, policy, database "
                "work and allowed connector execution. Denied and approval-required "
                "scenarios do not execute connectors."
                if endpoint == "/v1/execute"
                else "Client-observed latency excludes connector execution because /v1/evaluate is used."
            ),
            "Resource figures cover --server-pid when supplied; otherwise they cover the benchmark client.",
            "Run only against an isolated benchmark deployment: token issuance, audit events and rate limits mutate state.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-token", default=os.getenv("SENTINEL_ADMIN_TOKEN"))
    parser.add_argument("--concurrency", default="1,10,50,100")
    parser.add_argument("--requests-per-level", type=int, default=50)
    parser.add_argument("--server-pid", type=int)
    parser.add_argument(
        "--endpoint", choices=("/v1/evaluate", "/v1/execute"), default="/v1/execute"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.admin_token:
        parser.error("--admin-token or SENTINEL_ADMIN_TOKEN is required")
    levels = [int(item) for item in args.concurrency.split(",")]
    report = asyncio.run(
        run(
            args.base_url,
            args.admin_token,
            levels,
            args.requests_per_level,
            args.server_pid,
            args.endpoint,
        )
    )
    report["command"] = (
        "python -m sentinelgate.production_benchmark "
        f"--base-url {args.base_url} --concurrency {args.concurrency} "
        f"--requests-per-level {args.requests_per_level} --endpoint {args.endpoint}"
    )
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
