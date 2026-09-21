import hashlib
import json
from uuid import uuid4

from sentinelgate.field_taint import (
    build_uniform_field_taint,
    combine_field_taint,
    leaf_values,
    value_digest,
)
from sentinelgate.identity import TokenError, TokenSigner
from sentinelgate.models import (
    DataClassification,
    FieldTaint,
    ProvenanceAttestation,
    ProvenanceAttestRequest,
    StructuredProvenanceAttestRequest,
    StructuredProvenanceDeriveRequest,
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

    def attest_structured(
        self, request: StructuredProvenanceAttestRequest, tenant_id: str
    ) -> ProvenanceAttestation:
        content = json.dumps(
            request.value, sort_keys=True, separators=(",", ":"), default=str
        )
        if len(content.encode("utf-8")) > 1_000_000:
            raise ValueError("Structured provenance value exceeds 1 MB")
        signals = injection_signals(content)
        labels = sorted(
            {
                *[label.casefold() for label in request.labels],
                *({"prompt_injection"} if signals else set()),
            }
        )
        lineage_id = str(uuid4())
        leaves = leaf_values(request.value)
        if len(leaves) > 200 or len(request.field_overrides) > 200:
            raise ValueError("Structured provenance supports at most 200 leaf fields")
        field_taint = build_uniform_field_taint(
            request.value,
            trust=request.trust,
            classification=request.classification,
            labels=labels,
            lineage_ids=[lineage_id],
        )
        for pointer, override in request.field_overrides.items():
            if pointer not in leaves:
                raise ValueError(f"Field override does not resolve to a leaf: {pointer}")
            current = field_taint[pointer]
            field_taint[pointer] = FieldTaint(
                content_digest=current.content_digest,
                trust=TrustLevel(override.get("trust", current.trust.value)),
                classification=DataClassification(
                    override.get("classification", current.classification.value)
                ),
                labels=sorted(
                    {
                        *current.labels,
                        *[str(item).casefold() for item in override.get("labels", [])],
                    }
                ),
                lineage_ids=[lineage_id],
            )
        digest = value_digest(request.value)
        serialized_fields = {
            pointer: item.model_dump(mode="json")
            for pointer, item in field_taint.items()
        }
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
            field_taint=serialized_fields,
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
            field_taint=field_taint,
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
        field_taint: dict[str, FieldTaint] | None = None,
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
        inherited_fields = [
            item for parent in parents for item in parent.field_taint.values()
        ]
        if field_taint is None:
            field_taint = build_uniform_field_taint(
                output,
                trust=effective_trust,
                classification=effective_classification,
                labels=effective_labels,
                lineage_ids=[lineage_id, *parent_ids],
            )
        elif inherited_fields:
            # Connector-supplied field metadata may be more precise, but can never
            # be less restrictive than signed parent context.
            parent_trust = least_trusted(item.trust for item in inherited_fields)
            parent_classification = highest_classification(
                item.classification for item in inherited_fields
            )
            parent_labels = {label for item in inherited_fields for label in item.labels}
            field_taint = {
                pointer: FieldTaint(
                    content_digest=item.content_digest,
                    trust=least_trusted([item.trust, parent_trust]),
                    classification=highest_classification(
                        [item.classification, parent_classification]
                    ),
                    labels=sorted({*item.labels, *parent_labels}),
                    lineage_ids=sorted({*item.lineage_ids, lineage_id, *parent_ids}),
                )
                for pointer, item in field_taint.items()
            }
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
            field_taint={
                pointer: item.model_dump(mode="json")
                for pointer, item in field_taint.items()
            },
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
            field_taint=field_taint,
        )

    def derive_structured(
        self, request: StructuredProvenanceDeriveRequest, tenant_id: str
    ) -> ProvenanceAttestation:
        verified_inputs: dict[str, FieldTaint] = {}
        for name, item in request.inputs.items():
            verified = self.verify_many([item.reference.token], tenant_id)[0]
            if verified.trace_id and verified.trace_id != request.trace_id:
                raise TokenError("Derivation trace mismatch")
            field = verified.field_taint.get(item.reference.source_pointer)
            if field is None or field.content_digest != value_digest(item.value):
                raise TokenError("Derivation input is not bound to signed provenance")
            verified_inputs[name] = field

        outputs = leaf_values(request.value)
        field_taint: dict[str, FieldTaint] = {}
        if request.mode == "llm":
            combined = list(verified_inputs.values())
            for pointer, value in outputs.items():
                field_taint[pointer] = combine_field_taint(value, combined)
        else:
            if set(request.derivations) != set(outputs):
                raise ValueError("Every output leaf requires a deterministic derivation")
            for pointer, output_value in outputs.items():
                recipe = request.derivations[pointer]
                try:
                    values = [request.inputs[name].value for name in recipe.inputs]
                    sources = [verified_inputs[name] for name in recipe.inputs]
                except KeyError as exc:
                    raise ValueError("Derivation references an unknown input") from exc
                if recipe.operation == "copy":
                    if len(values) != 1:
                        raise ValueError("copy requires exactly one input")
                    computed = values[0]
                elif recipe.operation == "concat":
                    computed = recipe.separator.join(str(value) for value in values)
                elif recipe.operation == "template":
                    computed = recipe.template
                    for name in recipe.inputs:
                        computed = computed.replace(
                            "{" + name + "}", str(request.inputs[name].value)
                        )
                    if "{" in computed or "}" in computed:
                        raise ValueError("Template contains unresolved placeholders")
                else:
                    if len(values) != 1:
                        raise ValueError("substring requires exactly one input")
                    computed = str(values[0])[recipe.start : recipe.end]
                if computed != output_value:
                    raise ValueError(f"Derivation output mismatch at {pointer}")
                field_taint[pointer] = combine_field_taint(output_value, sources)

        content = json.dumps(
            request.value, sort_keys=True, separators=(",", ":"), default=str
        )
        signals = injection_signals(content)
        lineage_id = str(uuid4())
        parent_ids = sorted(
            {lineage for item in verified_inputs.values() for lineage in item.lineage_ids}
        )
        for pointer, item in field_taint.items():
            field_taint[pointer] = item.model_copy(
                update={"lineage_ids": sorted({*item.lineage_ids, lineage_id})}
            )
        trust = least_trusted(item.trust for item in field_taint.values())
        classification = highest_classification(
            item.classification for item in field_taint.values()
        )
        labels = sorted(
            {
                *[label for item in field_taint.values() for label in item.labels],
                *({"prompt_injection"} if signals else set()),
            }
        )
        digest = value_digest(request.value)
        token, expires = self.signer.issue(
            request.source_id,
            "sentinelgate-provenance",
            self.ttl_seconds,
            tenant_id=tenant_id,
            digest=digest,
            trust=trust.value,
            signals=signals,
            classification=classification.value,
            labels=labels,
            lineage_id=lineage_id,
            trace_id=request.trace_id,
            parent_ids=parent_ids,
            field_taint={
                pointer: item.model_dump(mode="json")
                for pointer, item in field_taint.items()
            },
        )
        return ProvenanceAttestation(
            token=token,
            content_digest=digest,
            trust=trust,
            signals=signals,
            classification=classification,
            labels=labels,
            lineage_id=lineage_id,
            trace_id=request.trace_id,
            expires_at=expires,
            field_taint=field_taint,
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
            raw_field_taint = payload.get("field_taint", {})
            if not isinstance(labels, list) or not all(isinstance(v, str) for v in labels):
                raise TokenError("Invalid provenance labels")
            if not isinstance(parent_ids, list) or not all(
                isinstance(v, str) for v in parent_ids
            ):
                raise TokenError("Invalid provenance parents")
            if not isinstance(raw_field_taint, dict) or len(raw_field_taint) > 1000:
                raise TokenError("Invalid field provenance")
            try:
                field_taint = {
                    str(pointer): FieldTaint.model_validate(item)
                    for pointer, item in raw_field_taint.items()
                }
            except (TypeError, ValueError) as exc:
                raise TokenError("Invalid field provenance") from exc
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
                    field_taint=field_taint,
                )
            )
        return verified

    def declassify_labels(
        self,
        *,
        token: str,
        tenant_id: str,
        paths: list[str],
        remove_labels: set[str],
        reviewer: str,
    ) -> ProvenanceAttestation:
        source = self.verify_many([token], tenant_id)[0]
        missing = [pointer for pointer in paths if pointer not in source.field_taint]
        if missing:
            raise TokenError("Declassification path is not present in signed provenance")
        lineage_id = str(uuid4())
        field_taint = dict(source.field_taint)
        for pointer in paths:
            current = field_taint[pointer]
            field_taint[pointer] = current.model_copy(
                update={
                    "labels": sorted(set(current.labels) - remove_labels),
                    "lineage_ids": sorted({*current.lineage_ids, lineage_id}),
                }
            )
        labels = sorted({label for item in field_taint.values() for label in item.labels})
        token_value, expires = self.signer.issue(
            f"declassified:{reviewer}",
            "sentinelgate-provenance",
            self.ttl_seconds,
            tenant_id=tenant_id,
            digest=source.content_digest,
            trust=source.trust.value,
            signals=source.signals,
            classification=source.classification.value,
            labels=labels,
            lineage_id=lineage_id,
            trace_id=source.trace_id,
            parent_ids=[source.lineage_id] if source.lineage_id else [],
            field_taint={
                pointer: item.model_dump(mode="json")
                for pointer, item in field_taint.items()
            },
            declassified_by=reviewer,
            removed_labels=sorted(remove_labels),
        )
        return ProvenanceAttestation(
            token=token_value,
            content_digest=source.content_digest,
            trust=source.trust,
            signals=source.signals,
            classification=source.classification,
            labels=labels,
            lineage_id=lineage_id,
            trace_id=source.trace_id,
            expires_at=expires,
            field_taint=field_taint,
        )
