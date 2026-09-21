"""Buyer- and auditor-readable evidence summaries without certification claims."""

from collections import Counter
from typing import Any

from sentinelgate.models import utc_now
from sentinelgate.settings import Settings
from sentinelgate.storage import Store


def security_evidence_report(store: Store, settings: Settings, limit: int = 500) -> dict[str, Any]:
    events = store.recent_audit(limit)
    decisions = [event for event in events if event["event_type"] == "policy_decision"]
    verdicts = Counter(str(event["payload"].get("decision", "unknown")) for event in decisions)
    risks = Counter(str(event["payload"].get("risk", "unknown")) for event in decisions)
    reasons = Counter(
        str(reason)
        for event in decisions
        for reason in event["payload"].get("reason_codes", [])
    )
    metrics = store.metrics()
    controls = [
        {
            "control": "Agent access is scoped and revocable",
            "evidence": ["registered_agents", "agent_token_issued", "agent_tokens_revoked"],
            "status": "implemented",
        },
        {
            "control": "Sensitive actions require deterministic policy review",
            "evidence": ["policy_decision", "approval_approved", "approval_rejected"],
            "status": "implemented",
        },
        {
            "control": "Data lineage and taint persist across tool calls",
            "evidence": ["tainted_traces", "provenance_attested"],
            "status": "implemented",
        },
        {
            "control": "Audit records are integrity checked",
            "evidence": ["audit_chain_valid"],
            "status": "passing" if store.verify_audit_chain() else "failed",
        },
        {
            "control": "MCP tool definitions are inspected and baselined",
            "evidence": ["mcp_tools_baselined", "mcp_manifest_inspected"],
            "status": "implemented",
        },
    ]
    return {
        "report": "SentinelGate security evidence",
        "schema_version": "1.0",
        "generated_at": utc_now().isoformat(),
        "product_version": "0.8.0",
        "enforcement_mode": settings.enforcement_mode.value,
        "scope": {"audit_events_considered": len(events), "maximum_events": limit},
        "integrity": {"audit_chain_valid": store.verify_audit_chain()},
        "metrics": metrics,
        "policy_decisions": {
            "total": len(decisions),
            "verdicts": dict(sorted(verdicts.items())),
            "risk_levels": dict(sorted(risks.items())),
            "top_reason_codes": [
                {"reason": reason, "count": count}
                for reason, count in reasons.most_common(10)
            ],
        },
        "control_evidence": controls,
        "disclaimer": (
            "This is an operational evidence summary, not a SOC 2, ISO 27001, "
            "HIPAA, GDPR, or other compliance certification."
        ),
    }
