"""Reproducible release evidence: performance, regression, probes and resilience."""

import argparse
import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path

from sentinelgate.adversarial_evaluation import run as run_adversarial
from sentinelgate.benchmark import run as run_performance
from sentinelgate.evaluation import run as run_evaluation
from sentinelgate.resilience import run as run_resilience


def run(iterations: int = 2000) -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    policy = root / "config" / "policies.json"
    corpus = root / "config" / "evaluation_corpus.json"
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "sentinelgate_version": "0.9.0",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "inputs": {
            "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
            "corpus_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
            "command": f"python -m sentinelgate.benchmark_suite --iterations {iterations}",
        },
        "performance": run_performance(iterations),
        "regression_conformance": run_evaluation(corpus),
        "adversarial_probes": run_adversarial(root / "config" / "adversarial_corpus.json"),
        "resilience": run_resilience(),
        "limitations": [
            "Local policy-path latency excludes network and connector latency.",
            "The bundled regression and adversarial corpora are project-authored and are not independent validation.",
            "Regression conformance is not an efficacy claim; adversarial misses are intentionally retained.",
            "Local thread tests do not establish multi-instance database correctness.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.iterations)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
