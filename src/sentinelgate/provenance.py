import hashlib
import json
from uuid import uuid4

from sentinelgate.identity import TokenError, TokenSigner
from sentinelgate.models import (
    DataClassification,
    ProvenanceAttestation,
    ProvenanceAttestRequest,
    TrustLevel,
    VerifiedProvenance,
)
from sentinelgate.security import injection_signals
from sentinelgate.taint import highest_classification, least_trusted


class ProvenanceService:
    def __init__(self, signer: TokenSigner, ttl_seconds: int = 3600):
        self.signer = signer
        self.ttl_seconds = ttl_seconds

    def attest(
        self, request: ProvenanceAttestRequest, tenant_id: str
    ) -> ProvenanceAttestation:
        digest = hashlib.sha256(request.content.encode("utf-8")).hexdigest()
        signals = injection_signals(request.content)
        labels = sorted(
            {
                *[label.casefold() for label in request.labels],
                *({"prompt_injection"} if signals else set()),
            }
        )
        lineage_id = str(uuid4())
        token, expires = self.signer.issue(
            request.source_id,
            "sentinelgate-provenance",
            self.ttl_seconds,
            tenant_id=tenant_id,
            digest=digest,
            trust=request.trust.value,
            signals=signals,
            classification=request.classification.value,
            labels=labels,
            lineage_id=lineage_id,
            trace_id=request.trace_id,
            parent_ids=[],
        )
        return ProvenanceAttestation(
            token=token,
            content_digest=digest,
            trust=request.trust,
            signals=signals,
            classification=request.classification,
            labels=labels,
            lineage_id=lineage_id,
            trace_id=request.trace_id,
            expires_at=expires,
        )

    def derive_tool_output(
        self,
        *,
        tenant_id: str,
        trace_id: str,
        request_id: str,
        tool_name: str,
        output: object,
        trust: TrustLevel,
        classification: DataClassification,
        labels: set[str],
        parents: list[VerifiedProvenance],
    ) -> ProvenanceAttestation:
        content = json.dumps(output, sort_keys=True, separators=(",", ":"), default=str)
        signals = injection_signals(content)
        effective_trust = least_trusted([trust, *[item.trust for item in parents]])
        effective_classification = highest_classification(
            [classification, *[item.classification for item in parents]]
        )
        effective_labels = sorted(
            {
                *labels,
                *[label for item in parents for label in item.labels],
                *({"prompt_injection"} if signals else set()),
            }
        )
        lineage_id = str(uuid4())
        parent_ids = sorted(
            {item.lineage_id for item in parents if item.lineage_id is not None}
        )
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        token, expires = self.signer.issue(
            f"tool:{tool_name}:{request_id}",
            "sentinelgate-provenance",
            self.ttl_seconds,
            tenant_id=tenant_id,
            digest=digest,
            trust=effective_trust.value,
            signals=signals,
            classification=effective_classification.value,
            labels=effective_labels,
            lineage_id=lineage_id,
            trace_id=trace_id,
            parent_ids=parent_ids,
        )
        return ProvenanceAttestation(
            token=token,
            content_digest=digest,
            trust=effective_trust,
            signals=signals,
            classification=effective_classification,
            labels=effective_labels,
            lineage_id=lineage_id,
            trace_id=trace_id,
            expires_at=expires,
        )

    def verify_many(
        self, tokens: list[str], tenant_id: str
    ) -> list[VerifiedProvenance]:
        verified: list[VerifiedProvenance] = []
        for token in tokens:
            payload = self.signer.decode(token, "sentinelgate-provenance")
            if payload.get("tenant_id") != tenant_id:
                raise TokenError("Provenance tenant mismatch")
            try:
                trust = TrustLevel(payload["trust"])
                classification = DataClassification(
                    payload.get("classification", DataClassification.PUBLIC.value)
                )
            except (KeyError, ValueError) as exc:
                raise TokenError("Invalid provenance trust") from exc
            signals = payload.get("signals", [])
            if not isinstance(signals, list) or not all(
                isinstance(v, str) for v in signals
            ):
                raise TokenError("Invalid provenance signals")
            labels = payload.get("labels", [])
            parent_ids = payload.get("parent_ids", [])
            if not isinstance(labels, list) or not all(isinstance(v, str) for v in labels):
                raise TokenError("Invalid provenance labels")
            if not isinstance(parent_ids, list) or not all(
                isinstance(v, str) for v in parent_ids
            ):
                raise TokenError("Invalid provenance parents")
            verified.append(
                VerifiedProvenance(
                    source_id=str(payload["sub"]),
                    content_digest=str(payload["digest"]),
                    trust=trust,
                    signals=signals,
                    classification=classification,
                    labels=labels,
                    lineage_id=str(payload["lineage_id"])
                    if payload.get("lineage_id")
                    else None,
                    trace_id=str(payload["trace_id"])
                    if payload.get("trace_id")
                    else None,
                    parent_ids=parent_ids,
                )
            )
        return verified
