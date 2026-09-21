"""Deterministic adversarial probes; explicitly not an independent efficacy test."""

import argparse
import json
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


def _arguments(field: str, value: str) -> dict[str, str]:
    arguments = {"to": "security@example.com", "subject": "Security report", "body": "Safe body"}
    arguments[field] = value
    return arguments


def run(path: Path | None = None) -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    corpus_path = path or root / "config" / "adversarial_corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    results: list[dict[str, object]] = []
    with TemporaryDirectory(prefix="sentinelgate-adversarial-") as directory:
        signer = TokenSigner("adversarial-token-signing-key-32", "adversarial")
        provenance = ProvenanceService(signer)
        service = GatewayService(
            PolicyEngine(root / "config" / "policies.json"),
            Store(Path(directory) / "evaluation.db", "adversarial-audit", "adversarial-encryption-key-32"),
            provenance,
            demo_registry(root / "knowledge"),
        )
        case_number = 0
        for family in corpus["families"]:
            for value in family["values"]:
                case_number += 1
                trace_id = f"adversarial-{case_number}"
                principal = AgentPrincipal(
                    agent_id=family["agent_id"], tenant_id="adversarial",
                    scopes=frozenset(family["scopes"]), token_id=trace_id,
                    expires_at=utc_now() + timedelta(hours=1),
                )
                arguments = _arguments(family["argument_field"], value)
                field_provenance = {}
                structured = family.get("structured")
                if structured:
                    attestation = provenance.attest_structured(
                        StructuredProvenanceAttestRequest(
                            source_id=f"corpus:{case_number}", value=arguments,
                            trust=TrustLevel(structured["trust"]),
                            classification=DataClassification(structured["classification"]),
                            labels=structured["labels"], trace_id=trace_id,
                        ),
                        principal.tenant_id,
                    )
                    pointer = f"/{family['argument_field']}"
                    field_provenance[pointer] = [
                        FieldProvenanceReference(token=attestation.token, source_pointer=pointer)
                    ]
                decision = service.evaluate(
                    ToolCallRequest(
                        user_id="adversarial", tool_name=family["tool"], arguments=arguments,
                        trace_id=trace_id, field_provenance=field_provenance,
                    ),
                    principal,
                    side_effects=False,
                )
                results.append(
                    {
                        "id": case_number,
                        "family": family["name"],
                        "class": family["class"],
                        "expected": family["expected"],
                        "actual": decision.decision.value,
                        "passed": decision.decision.value == family["expected"],
                        "reasons": decision.reason_codes,
                    }
                )
    attacks = [item for item in results if item["class"] == "attack"]
    benign = [item for item in results if item["class"] == "benign"]
    misses = [item for item in attacks if item["actual"] != "deny"]
    false_positives = [item for item in benign if item["actual"] == "deny"]
    return {
        "corpus_version": corpus["version"],
        "scope": "project-authored adversarial probes; not independent validation",
        "references": corpus["references"],
        "cases": len(results),
        "attack_cases": len(attacks),
        "benign_cases": len(benign),
        "attack_denial_rate": round((len(attacks) - len(misses)) / len(attacks), 4),
        "benign_denial_rate": round(len(false_positives) / len(benign), 4),
        "misses": misses,
        "false_positives": false_positives,
        "results": results,
        "warning": "These measurements characterize this build only; they are not a general prompt-injection efficacy claim.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.corpus)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
