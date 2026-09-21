import fnmatch
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelgate.models import (
    AgentPrincipal,
    DataClassification,
    Decision,
    SecurityFinding,
    ToolCallRequest,
    TrustLevel,
    VerifiedProvenance,
)
from sentinelgate.taint import classification_exceeds, highest_classification


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    reasons: list[str]
    risk: str
    policy_version: str


class PolicyConfigurationError(RuntimeError):
    pass


class PolicyEngine:
    """Deterministic authorization. Models may add signals, never grant access."""

    def __init__(self, policy_path: Path):
        self.policy_path = policy_path
        self._policy = self._load()
        self._runtime_tools: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_mapping(cls, policy: dict[str, Any]) -> "PolicyEngine":
        if len(json.dumps(policy, separators=(",", ":"), default=str)) > 1_000_000:
            raise PolicyConfigurationError("Replay policy exceeds 1 MB")
        instance = cls.__new__(cls)
        instance.policy_path = Path("<replay>")
        instance._policy = deepcopy(policy)
        instance._runtime_tools = {}
        instance._validate(instance._policy)
        return instance

    def _load(self) -> dict[str, Any]:
        try:
            policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyConfigurationError(f"Cannot load policy: {exc}") from exc
        self._validate(policy)
        return policy

    @staticmethod
    def _validate(policy: dict[str, Any]) -> None:
        if not isinstance(policy, dict):
            raise PolicyConfigurationError("Policy must be an object")
        if not isinstance(policy.get("tools"), dict) or not policy.get("version"):
            raise PolicyConfigurationError("Policy requires version and tools")
        if len(policy["tools"]) > 500:
            raise PolicyConfigurationError("Policy contains too many tools")

    @property
    def version(self) -> str:
        return str(self._policy["version"])

    @property
    def defaults(self) -> dict[str, Any]:
        return self._policy.get("defaults", {})

    def tool_config(self, tool_name: str) -> dict[str, Any] | None:
        tool = self._runtime_tools.get(tool_name, self._policy["tools"].get(tool_name))
        return dict(tool) if isinstance(tool, dict) else None

    def register_runtime_tool(self, tool_name: str, config: dict[str, Any]) -> None:
        if tool_name in self._policy["tools"]:
            raise PolicyConfigurationError(
                f"Runtime tool collides with configured tool: {tool_name}"
            )
        existing = self._runtime_tools.get(tool_name)
        if existing is not None and existing != config:
            raise PolicyConfigurationError(
                f"Runtime tool policy changed during process lifetime: {tool_name}"
            )
        self._runtime_tools[tool_name] = deepcopy(config)

    def as_mapping(self) -> dict[str, Any]:
        """Return an isolated copy for inspection and side-effect-free replay."""
        return deepcopy(self._policy)

    def evaluate(
        self,
        call: ToolCallRequest,
        principal: AgentPrincipal,
        provenance: list[VerifiedProvenance],
        findings: list[SecurityFinding],
    ) -> Evaluation:
        tool = self.tool_config(call.tool_name)
        if tool is None:
            return self._deny("UNKNOWN_TOOL", "critical")

        risk = str(tool.get("risk", "high"))
        allowed_agents = tool.get("allowed_agents", [])
        if principal.agent_id not in allowed_agents:
            return self._deny("AGENT_NOT_AUTHORIZED", risk)

        required_scopes = set(tool.get("required_scopes", []))
        missing_scopes = sorted(required_scopes - set(principal.scopes))
        if missing_scopes:
            return Evaluation(
                Decision.DENY,
                [f"MISSING_SCOPE:{scope}" for scope in missing_scopes],
                risk,
                self.version,
            )

        max_length = int(
            tool.get(
                "max_string_length",
                self.defaults.get("max_string_length", 10_000),
            )
        )
        if self._contains_oversized_string(call.arguments, max_length):
            return self._deny("ARGUMENT_TOO_LARGE", risk)

        blocked: list[str] = []
        for field, patterns in tool.get("blocked_argument_patterns", {}).items():
            value = str(call.arguments.get(field, ""))
            if any(fnmatch.fnmatch(value.casefold(), p.casefold()) for p in patterns):
                blocked.append(f"BLOCKED_ARGUMENT:{field}")
        if blocked:
            return Evaluation(Decision.DENY, blocked, risk, self.version)

        is_sensitive = bool(tool.get("sensitive", False))
        if tool.get("requires_provenance", False) and not provenance:
            return self._deny("MISSING_PROVENANCE", risk)
        if is_sensitive and any(
            item.trust is TrustLevel.UNTRUSTED for item in provenance
        ):
            return self._deny("UNTRUSTED_SOURCE_TO_SENSITIVE_TOOL", risk)
        if is_sensitive and any(item.signals for item in provenance):
            signals = sorted({signal for item in provenance for signal in item.signals})
            return Evaluation(
                Decision.DENY,
                [
                    "PROMPT_INJECTION_SIGNAL",
                    *[f"SIGNAL:{signal}" for signal in signals],
                ],
                risk,
                self.version,
            )

        labels = {label for item in provenance for label in item.labels}
        blocked_labels = set(tool.get("blocked_taint_labels", []))
        matched_labels = sorted(labels & blocked_labels)
        if matched_labels:
            return Evaluation(
                Decision.DENY,
                [f"TAINT_LABEL:{label}" for label in matched_labels],
                "critical",
                self.version,
            )

        maximum = tool.get("max_input_classification")
        if maximum and provenance:
            try:
                maximum_classification = DataClassification(maximum)
            except ValueError:
                return self._deny("INVALID_MAX_INPUT_CLASSIFICATION", "critical")
            actual = highest_classification(item.classification for item in provenance)
            if classification_exceeds(actual, maximum_classification):
                action = tool.get("classification_violation_action", "deny")
                decision = (
                    Decision.REQUIRE_APPROVAL
                    if action == "require_approval"
                    else Decision.DENY
                )
                return Evaluation(
                    decision,
                    [
                        "CLASSIFICATION_FLOW_BLOCKED",
                        f"CLASSIFICATION:{actual.value}",
                        f"MAX_ALLOWED:{maximum_classification.value}",
                    ],
                    "critical",
                    self.version,
                )

        if findings and tool.get("egress", False):
            action = tool.get("dlp_action", "require_approval")
            codes = sorted({f"DLP:{finding.code}" for finding in findings})
            if action == "deny":
                return Evaluation(Decision.DENY, codes, "critical", self.version)
            return Evaluation(Decision.REQUIRE_APPROVAL, codes, risk, self.version)

        try:
            effect = Decision(tool.get("effect", "deny"))
        except ValueError:
            return self._deny("INVALID_POLICY_EFFECT", risk)

        reasons = [f"POLICY_EFFECT:{effect.value}"]
        if is_sensitive and any(item.trust is TrustLevel.MIXED for item in provenance):
            effect = Decision.REQUIRE_APPROVAL
            reasons.append("MIXED_TRUST_REQUIRES_APPROVAL")
        return Evaluation(effect, reasons, risk, self.version)

    def _deny(self, reason: str, risk: str) -> Evaluation:
        return Evaluation(Decision.DENY, [reason], risk, self.version)

    @classmethod
    def _contains_oversized_string(cls, value: Any, limit: int) -> bool:
        if isinstance(value, str):
            return len(value) > limit
        if isinstance(value, dict):
            return any(cls._contains_oversized_string(v, limit) for v in value.values())
        if isinstance(value, list):
            return any(cls._contains_oversized_string(v, limit) for v in value)
        return False
