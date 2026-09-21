"""Versioned regression evaluation. This is not an efficacy claim."""

import argparse
import json
import platform
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelgate.executor import demo_registry
from sentinelgate.identity import TokenSigner
from sentinelgate.models import (
    AgentPrincipal,
    DataClassification,
    FieldProvenanceReference,
    StructuredProvenanceAttestRequest,
    ToolCallRequest,
    TrustLevel,
    utc_now,
)
from sentinelgate.policy import PolicyEngine
from sentinelgate.provenance import ProvenanceService
from sentinelgate.service import GatewayService
from sentinelgate.storage import Store


def run(corpus_path: Path | None = None) -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    path = corpus_path or root / "config" / "evaluation_corpus.json"
    corpus = json.loads(path.read_text(encoding="utf-8"))
    results: list[dict[str, object]] = []
    with TemporaryDirectory(prefix="sentinelgate-evaluation-") as directory:
        signer = TokenSigner("evaluation-token-signing-key-32", "evaluation")
        provenance = ProvenanceService(signer)
        service = GatewayService(
            PolicyEngine(root / "config" / "policies.json"),
            Store(
                Path(directory) / "evaluation.db",
                "evaluation-audit-key",
                "evaluation-encryption-key-32-bytes",
            ),
            provenance,
            demo_registry(root / "knowledge"),
        )
        for index, case in enumerate(corpus["cases"]):
            trace_id = f"evaluation-{index}"
            principal = AgentPrincipal(
                agent_id=case["agent_id"], tenant_id="evaluation",
                scopes=frozenset(case["scopes"]), token_id=f"evaluation-{index}",
                expires_at=utc_now() + timedelta(hours=1),
            )
            field_provenance = {}
            structured = case.get("structured")
            if structured:
                attestation = provenance.attest_structured(
                    StructuredProvenanceAttestRequest(
                        source_id=f"corpus:{case['name']}",
                        value=structured["value"],
                        trust=TrustLevel(structured.get("trust", "untrusted")),
                        classification=DataClassification(
                            structured.get("classification", "public")
                        ),
                        labels=structured.get("labels", []),
                        field_overrides=structured.get("field_overrides", {}),
                        trace_id=trace_id,
                    ),
                    principal.tenant_id,
                )
                field_provenance = {
                    destination: [
                        FieldProvenanceReference(
                            token=attestation.token, source_pointer=source
                        )
                    ]
                    for destination, source in structured.get("bind", {}).items()
                }
            call = ToolCallRequest(
                user_id="evaluation", tool_name=case["tool"],
                arguments=case["arguments"], trace_id=trace_id,
                field_provenance=field_provenance,
            )
            decision = service.evaluate(call, principal, side_effects=False)
            actual = decision.decision.value
            results.append(
                {
                    "name": case["name"], "class": case["class"],
                    "expected": case["expected"], "actual": actual,
                    "passed": actual == case["expected"],
                    "reasons": decision.reason_codes,
                }
            )
    attacks = [item for item in results if item["class"] == "attack"]
    benign = [item for item in results if item["class"] == "benign"]
    detected = sum(item["actual"] != "allow" for item in attacks)
    false_positives = sum(item["actual"] == "deny" for item in benign)
    return {
        "corpus_version": corpus["version"],
        "scope": "deterministic regression conformance only; not an efficacy claim or independent validation",
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "cases": len(results),
        "exact_match_rate": round(sum(item["passed"] for item in results) / len(results), 4),
        "attack_detection_rate": round(detected / len(attacks), 4) if attacks else None,
        "benign_false_positive_rate": round(false_positives / len(benign), 4) if benign else None,
        "results": results,
        "warning": "A passing regression means configured rules behaved as expected; it does not estimate resistance to novel attacks.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.corpus), indent=2))


if __name__ == "__main__":
    main()
