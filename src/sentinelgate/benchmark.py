"""Reproducible local policy-path microbenchmark; excludes network connectors."""

import argparse
import json
import statistics
import tempfile
import time
from datetime import timedelta
from pathlib import Path

from sentinelgate.executor import demo_registry
from sentinelgate.identity import TokenSigner
from sentinelgate.models import AgentPrincipal, ToolCallRequest, utc_now
from sentinelgate.policy import PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store


def percentile(values: list[float], percentage: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * percentage))
    return ordered[index]


def run(iterations: int) -> dict[str, object]:
    if iterations < 100:
        raise ValueError("iterations must be at least 100")
    root = Path(__file__).resolve().parents[2]
    signer = TokenSigner("benchmark-token-signing-key-32-bytes", "benchmark")
    principal = AgentPrincipal(
        agent_id="research-agent",
        tenant_id="benchmark",
        scopes=frozenset({"tools:search"}),
        token_id="benchmark-token",  # nosec B106
        expires_at=utc_now() + timedelta(hours=1),
    )
    call = ToolCallRequest(
        user_id="benchmark",
        tool_name="search_knowledge",
        arguments={"query": "security policy"},
        trace_id="benchmark-trace",
    )
    with tempfile.TemporaryDirectory(prefix="sentinelgate-benchmark-") as directory:
        service = GatewayService(
            PolicyEngine(root / "config" / "policies.json"),
            Store(
                Path(directory) / "benchmark.db",
                "benchmark-audit-key",
                "benchmark-data-encryption-key-32-bytes",
            ),
            ProvenanceService(signer),
            demo_registry(root / "knowledge"),
        )
        for _ in range(25):
            service.evaluate(call, principal, side_effects=False)
        samples: list[float] = []
        started = time.perf_counter()
        for _ in range(iterations):
            before = time.perf_counter()
            service.evaluate(call, principal, side_effects=False)
            samples.append((time.perf_counter() - before) * 1000)
        elapsed = time.perf_counter() - started
    return {
        "benchmark": "local_policy_evaluation",
        "scope": "identity, policy, schema, DLP and SQLite reads; excludes HTTP and connectors",
        "iterations": iterations,
        "latency_ms": {
            "p50": round(percentile(samples, 0.50), 3),
            "p95": round(percentile(samples, 0.95), 3),
            "p99": round(percentile(samples, 0.99), 3),
            "mean": round(statistics.fmean(samples), 3),
        },
        "throughput_rps": round(iterations / elapsed, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2_000)
    args = parser.parse_args()
    print(json.dumps(run(args.iterations), indent=2))


if __name__ == "__main__":
    main()
