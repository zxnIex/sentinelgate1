"""Deterministic inspection and integrity baselining for MCP tool manifests."""

import hashlib
import re
import unicodedata
from typing import Any

from sentinelgate.models import (
    MCPManifestInspectionRequest,
    MCPManifestInspectionResult,
    MCPToolFinding,
    MCPToolInspection,
    utc_now,
)
from sentinelgate.security import canonical_json, injection_signals
from sentinelgate.storage import Store

SENSITIVE_SCHEMA_NAMES = re.compile(
    r"(?i)(system[_-]?prompt|developer[_-]?message|authorization|cookie|private[_-]?key|secret|token)"
)
CONTROL_CATEGORIES = {"Cf", "Cc"}


def _schema_paths(value: Any, path: str = "inputSchema") -> list[str]:
    matches: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SENSITIVE_SCHEMA_NAMES.search(str(key)):
                matches.append(child_path)
            matches.extend(_schema_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(_schema_paths(child, f"{path}[{index}]"))
    return matches


def _has_hidden_controls(value: str) -> bool:
    return any(
        unicodedata.category(character) in CONTROL_CATEGORIES
        and character not in {"\n", "\r", "\t"}
        for character in value
    )


def inspect_manifest(
    server_id: str,
    request: MCPManifestInspectionRequest,
    store: Store,
) -> MCPManifestInspectionResult:
    results: list[MCPToolInspection] = []
    definitions = [tool.model_dump(mode="json") for tool in request.tools]
    counts = {tool.name: 0 for tool in request.tools}
    for tool in request.tools:
        counts[tool.name] += 1

    for tool, definition in zip(request.tools, definitions, strict=True):
        digest = hashlib.sha256(canonical_json(definition).encode("utf-8")).hexdigest()
        baseline = store.get_mcp_tool_baseline(server_id, tool.name)
        baseline_digest = str(baseline["digest"]) if baseline else None
        changed = baseline_digest is not None and baseline_digest != digest
        findings: list[MCPToolFinding] = []

        for signal in injection_signals(tool.description):
            findings.append(MCPToolFinding(
                code=f"DESCRIPTION_{signal}", severity="critical",
                location="description",
                detail="Instruction-like content appeared in the tool description.",
            ))
        schema_text = canonical_json(tool.inputSchema)
        for signal in injection_signals(schema_text):
            findings.append(MCPToolFinding(
                code=f"SCHEMA_{signal}", severity="critical",
                location="inputSchema",
                detail="Instruction-like content appeared in the input schema.",
            ))
        if _has_hidden_controls(tool.description) or _has_hidden_controls(schema_text):
            findings.append(MCPToolFinding(
                code="HIDDEN_UNICODE_CONTROL", severity="critical",
                location="definition",
                detail="The definition contains non-printing control characters.",
            ))
        for path in sorted(set(_schema_paths(tool.inputSchema))):
            findings.append(MCPToolFinding(
                code="SENSITIVE_SCHEMA_FIELD", severity="high", location=path,
                detail="The schema requests a credential- or prompt-like field.",
            ))
        if counts[tool.name] > 1:
            findings.append(MCPToolFinding(
                code="DUPLICATE_TOOL_NAME", severity="critical", location="name",
                detail="The same manifest declares this tool name more than once.",
            ))
        owners = store.mcp_tool_name_owners(tool.name, server_id)
        if owners:
            findings.append(MCPToolFinding(
                code="CROSS_SERVER_NAME_COLLISION", severity="high", location="name",
                detail=f"Also registered by: {', '.join(owners[:5])}",
            ))
        if changed:
            findings.append(MCPToolFinding(
                code="TOOL_DEFINITION_CHANGED", severity="critical", location="definition",
                detail="The definition differs from the accepted baseline.",
            ))

        blocking_findings = [
            item
            for item in findings
            if item.severity == "critical"
            and not (
                request.accept_baseline and item.code == "TOOL_DEFINITION_CHANGED"
            )
        ]
        blocked = bool(blocking_findings)
        status = "blocked" if blocked else "review" if findings else "trusted"
        store.record_mcp_tool_observation(
            server_id,
            tool.name,
            digest,
            status,
            [item.code for item in findings],
        )
        first_seen_clean = baseline is None and not findings
        unchanged_clean = baseline is not None and not changed and not findings
        if (request.accept_baseline and not blocked) or first_seen_clean or unchanged_clean:
            store.upsert_mcp_tool_baseline(server_id, tool.name, digest, definition, status)
        results.append(MCPToolInspection(
            server_id=server_id, tool_name=tool.name, digest=digest,
            baseline_digest=baseline_digest, status=status, changed=changed,
            findings=findings,
        ))

    safe = all(item.status != "blocked" for item in results)
    accepted = safe and all(
        store.get_mcp_tool_baseline(server_id, item.tool_name) is not None
        for item in results
    )
    store.append_audit("mcp_manifest_inspected", {
        "server_id": server_id, "safe": safe, "accepted": accepted,
        "tools": [{
            "name": item.tool_name, "digest": item.digest, "status": item.status,
            "findings": [finding.code for finding in item.findings],
        } for item in results],
    })
    return MCPManifestInspectionResult(
        server_id=server_id, safe=safe, accepted=accepted,
        inspected_at=utc_now(), tools=results,
    )
