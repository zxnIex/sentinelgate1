"""Deterministic, value-bound field provenance using RFC 6901 JSON pointers."""

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from sentinelgate.models import DataClassification, FieldTaint, TrustLevel
from sentinelgate.taint import highest_classification, least_trusted


class FieldTaintError(ValueError):
    pass


def canonical_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def value_digest(value: Any) -> str:
    return hashlib.sha256(canonical_value(value).encode("utf-8")).hexdigest()


def escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def unescape_pointer(value: str) -> str:
    result = value.replace("~1", "/").replace("~0", "~")
    if "~" in result and any(part not in {"~0", "~1"} for part in []):
        raise FieldTaintError("Invalid JSON pointer escape")
    return result


def leaf_values(value: Any, pointer: str = "") -> dict[str, Any]:
    if isinstance(value, dict) and value:
        result: dict[str, Any] = {}
        for key, child in value.items():
            child_pointer = f"{pointer}/{escape_pointer(str(key))}"
            result.update(leaf_values(child, child_pointer))
        return result
    if isinstance(value, list) and value:
        result = {}
        for index, child in enumerate(value):
            result.update(leaf_values(child, f"{pointer}/{index}"))
        return result
    return {pointer: value}


def resolve_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise FieldTaintError("JSON pointer must be empty or start with '/'")
    current = value
    for encoded in pointer[1:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise FieldTaintError(f"JSON pointer does not resolve: {pointer}")
    return current


def build_uniform_field_taint(
    value: Any,
    *,
    trust: TrustLevel,
    classification: DataClassification,
    labels: Iterable[str],
    lineage_ids: Iterable[str],
) -> dict[str, FieldTaint]:
    return {
        pointer: FieldTaint(
            content_digest=value_digest(item),
            trust=trust,
            classification=classification,
            labels=sorted(set(labels)),
            lineage_ids=sorted(set(lineage_ids)),
        )
        for pointer, item in leaf_values(value).items()
    }


def combine_field_taint(
    value: Any,
    sources: Iterable[FieldTaint],
) -> FieldTaint:
    items = list(sources)
    return FieldTaint(
        content_digest=value_digest(value),
        trust=least_trusted(item.trust for item in items),
        classification=highest_classification(item.classification for item in items),
        labels=sorted({label for item in items for label in item.labels}),
        lineage_ids=sorted({lineage for item in items for lineage in item.lineage_ids}),
    )

