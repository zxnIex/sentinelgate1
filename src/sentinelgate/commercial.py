"""Commercial plans and server-side entitlement enforcement.

Stripe is a billing ledger, not the authorization source. SentinelGate stores a
small, webhook-derived subscription projection and computes every entitlement
server-side from this versioned catalogue.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sentinelgate.models import (
    EntitlementSnapshot,
    ProductPlan,
    TenantSubscription,
    utc_now,
)
from sentinelgate.storage import Store


class EntitlementError(PermissionError):
    def __init__(self, message: str, *, code: str = "UPGRADE_REQUIRED"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PlanDefinition:
    plan: ProductPlan
    name: str
    monthly_price_gbp: int | None
    included_agents: int | None
    decision_limit_monthly: int | None
    watch_event_limit_monthly: int | None
    llm_analysis_limit_monthly: int | None
    retention_days: int | None
    features: frozenset[str]


PLAN_CATALOGUE: dict[ProductPlan, PlanDefinition] = {
    ProductPlan.GATE_FREE: PlanDefinition(
        ProductPlan.GATE_FREE,
        "Gate Free",
        0,
        10,
        50_000,
        0,
        0,
        7,
        frozenset({"gate", "provenance", "approvals", "mcp_firewall"}),
    ),
    ProductPlan.GATE: PlanDefinition(
        ProductPlan.GATE,
        "Gate",
        49,
        50,
        500_000,
        0,
        0,
        30,
        frozenset({"gate", "provenance", "approvals", "mcp_firewall", "reporting"}),
    ),
    ProductPlan.WATCH: PlanDefinition(
        ProductPlan.WATCH,
        "Watch",
        199,
        50,
        1_000_000,
        1_000_000,
        0,
        30,
        frozenset(
            {
                "gate",
                "provenance",
                "approvals",
                "mcp_firewall",
                "reporting",
                "watch",
                "watch_notifications",
                "watch_baselines",
            }
        ),
    ),
    ProductPlan.WATCH_PLUS: PlanDefinition(
        ProductPlan.WATCH_PLUS,
        "Watch+",
        499,
        100,
        3_000_000,
        3_000_000,
        500,
        90,
        frozenset(
            {
                "gate",
                "provenance",
                "approvals",
                "mcp_firewall",
                "reporting",
                "watch",
                "watch_notifications",
                "watch_baselines",
                "watch_intelligence",
                "watch_response",
                "counterfactual_replay",
            }
        ),
    ),
    ProductPlan.ENTERPRISE: PlanDefinition(
        ProductPlan.ENTERPRISE,
        "Enterprise",
        None,
        None,
        None,
        None,
        None,
        None,
        frozenset(
            {
                "gate",
                "provenance",
                "approvals",
                "mcp_firewall",
                "reporting",
                "watch",
                "watch_notifications",
                "watch_baselines",
                "watch_intelligence",
                "watch_response",
                "counterfactual_replay",
                "enterprise_controls",
            }
        ),
    ),
}


ACTIVE_STATUSES = {"active", "trialing"}
PAST_DUE_GRACE = timedelta(days=7)


class EntitlementService:
    def __init__(self, store: Store, enforcement_enabled: bool):
        self.store = store
        self.enforcement_enabled = enforcement_enabled

    def _effective_subscription(self, tenant_id: str) -> TenantSubscription | None:
        subscription = self.store.get_tenant_subscription(tenant_id)
        if subscription and subscription.status in ACTIVE_STATUSES:
            return subscription
        if subscription and subscription.status == "past_due":
            grace_anchor = subscription.current_period_end or subscription.updated_at
            if utc_now() <= grace_anchor + PAST_DUE_GRACE:
                return subscription
        return None

    def snapshot(self, tenant_id: str) -> EntitlementSnapshot:
        recorded_subscription = self.store.get_tenant_subscription(tenant_id)
        subscription = self._effective_subscription(tenant_id)
        if not self.enforcement_enabled:
            plan = ProductPlan.ENTERPRISE
            status = "self_hosted"
            extra_agents = 0
        elif subscription is None:
            plan = ProductPlan.GATE_FREE
            status = "free"
            extra_agents = 0
        else:
            plan = subscription.plan
            status = subscription.status
            extra_agents = subscription.extra_agents
        definition = PLAN_CATALOGUE[plan]
        usage = self.store.tenant_usage(tenant_id)
        agent_limit = (
            definition.included_agents + extra_agents
            if definition.included_agents is not None
            else None
        )
        return EntitlementSnapshot(
            tenant_id=tenant_id,
            plan=plan,
            subscription_status=status,
            features=sorted(definition.features),
            agent_limit=agent_limit,
            decision_limit_monthly=definition.decision_limit_monthly,
            watch_event_limit_monthly=definition.watch_event_limit_monthly,
            llm_analysis_limit_monthly=definition.llm_analysis_limit_monthly,
            retention_days=definition.retention_days,
            usage=usage,
            billing_attention=(
                recorded_subscription is not None
                and recorded_subscription.status == "past_due"
            ),
            enforcement_enabled=self.enforcement_enabled,
        )

    def require_feature(self, tenant_id: str, feature: str) -> EntitlementSnapshot:
        snapshot = self.snapshot(tenant_id)
        if feature not in snapshot.features:
            raise EntitlementError(
                f"{feature.replace('_', ' ').title()} requires a higher SentinelGate plan"
            )
        return snapshot

    def require_agent_capacity(self, tenant_id: str, agent_id: str) -> None:
        snapshot = self.snapshot(tenant_id)
        if self.store.agent_is_active(tenant_id, agent_id):
            return
        if (
            snapshot.agent_limit is not None
            and snapshot.usage["agents"] >= snapshot.agent_limit
        ):
            raise EntitlementError(
                f"Agent allowance reached ({snapshot.agent_limit}); upgrade or add capacity",
                code="AGENT_LIMIT_REACHED",
            )

    def require_decision_capacity(self, tenant_id: str) -> None:
        snapshot = self.snapshot(tenant_id)
        limit = snapshot.decision_limit_monthly
        if limit is not None and snapshot.usage["decisions_month"] >= limit:
            raise EntitlementError(
                "Monthly Gate decision allowance reached", code="DECISION_LIMIT_REACHED"
            )

    def require_watch_capacity(self, tenant_id: str) -> EntitlementSnapshot:
        snapshot = self.require_feature(tenant_id, "watch")
        limit = snapshot.watch_event_limit_monthly
        if limit is not None and snapshot.usage["watch_events_month"] >= limit:
            raise EntitlementError(
                "Monthly Watch event allowance reached", code="WATCH_LIMIT_REACHED"
            )
        return snapshot

    def require_llm_capacity(self, tenant_id: str) -> EntitlementSnapshot:
        snapshot = self.require_feature(tenant_id, "watch_intelligence")
        limit = snapshot.llm_analysis_limit_monthly
        if limit is not None and snapshot.usage["llm_analyses_month"] >= limit:
            raise EntitlementError(
                "Monthly Watch+ intelligence allowance reached",
                code="LLM_ANALYSIS_LIMIT_REACHED",
            )
        return snapshot
