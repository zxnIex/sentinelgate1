import hashlib
import json
import re
from typing import Any

from sentinelgate.models import AgentPrincipal, SecurityFinding, ToolCallRequest

SECRET_KEY_NAMES = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|(?:access[_-]?)?tokens?|private[_-]?key)"
)
SECRET_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]
INJECTION_PATTERNS = [
    (
        "IGNORE_INSTRUCTIONS",
        re.compile(
            r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b"
        ),
    ),
    (
        "SYSTEM_PROMPT_REQUEST",
        re.compile(
            r"(?i)\b(?:reveal|print|show|exfiltrate)\b.{0,30}\b(?:system|developer)\s+prompt\b"
        ),
    ),
    (
        "SECRET_EXFILTRATION",
        re.compile(
            r"(?i)\b(?:send|upload|post|email)\b.{0,40}\b(?:secret|credential|token|api key)s?\b"
        ),
    ),
    (
        "TOOL_OVERRIDE",
        re.compile(
            r"(?i)\b(?:call|invoke|use)\b.{0,30}\b(?:admin|delete|shell|email)\b.{0,30}\btool\b"
        ),
    ),
]


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def request_hash(call: ToolCallRequest, principal: AgentPrincipal) -> str:
    body = {
        "agent_id": principal.agent_id,
        "tenant_id": principal.tenant_id,
        "call": call.model_dump(mode="json"),
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def scan_secrets(value: Any, path: str = "$") -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SECRET_KEY_NAMES.search(str(key)) and isinstance(child, str) and child:
                findings.append(
                    SecurityFinding(
                        code="SENSITIVE_FIELD",
                        severity="high",
                        path=child_path,
                        fingerprint=fingerprint(child),
                    )
                )
            findings.extend(scan_secrets(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(scan_secrets(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        for code, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(value):
                findings.append(
                    SecurityFinding(
                        code=code,
                        severity="critical",
                        path=path,
                        fingerprint=fingerprint(match.group(0)),
                    )
                )
    unique = {(f.code, f.path, f.fingerprint): f for f in findings}
    return list(unique.values())


def injection_signals(content: str) -> list[str]:
    return sorted(
        {code for code, pattern in INJECTION_PATTERNS if pattern.search(content)}
    )


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if SECRET_KEY_NAMES.search(str(key)):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(child)
        return result
    if isinstance(value, list):
        return [redact(child) for child in value]
    if isinstance(value, str):
        output = value
        for _, pattern in SECRET_PATTERNS:
            output = pattern.sub("[REDACTED]", output)
        return output
    return value
