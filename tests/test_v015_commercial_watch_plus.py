import hashlib
import hmac
import json
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from sentinelgate.api import app
from sentinelgate.billing import (
    BillingError,
    BillingWebhookProcessor,
    StripeWebhookVerifier,
)
from sentinelgate.commercial import EntitlementError, EntitlementService
from sentinelgate.models import (
    ProductPlan,
    ResponsePolicy,
    TenantSubscription,
    WatchEventRequest,
    WatchEventType,
    WatchTaskCreateRequest,
    utc_now,
)
from sentinelgate.respond import RespondError, RespondService
from sentinelgate.watch import WatchService
from sentinelgate.watch_intelligence import (
    WatchIntelligenceError,
    WatchIntelligenceService,
)


def _watch_principal(principal, token_id="watch-token"):
    return principal.model_copy(
        update={
            "token_id": token_id,
            "scopes": frozenset({*principal.scopes, "watch:write"}),
        }
    )


def _subscription(tenant_id, plan, status="active", extra_agents=0):
    return TenantSubscription(
        tenant_id=tenant_id,
        plan=plan,
        status=status,
        extra_agents=extra_agents,
        updated_at=utc_now(),
    )


def test_free_gate_has_ten_agent_allowance_and_watch_is_paid(store):
    service = EntitlementService(store, enforcement_enabled=True)
    snapshot = service.snapshot("new-tenant")
    assert snapshot.plan is ProductPlan.GATE_FREE
    assert snapshot.agent_limit == 10
    assert "gate" in snapshot.features
    assert "watch" not in snapshot.features
    with pytest.raises(EntitlementError, match="higher SentinelGate plan"):
        service.require_watch_capacity("new-tenant")

    store.upsert_tenant_subscription(_subscription("new-tenant", ProductPlan.WATCH))
    paid = service.require_watch_capacity("new-tenant")
    assert paid.plan is ProductPlan.WATCH
    assert "watch_intelligence" not in paid.features


def test_disabled_billing_preserves_self_hosted_development(store):
    snapshot = EntitlementService(store, enforcement_enabled=False).snapshot("local")
    assert snapshot.plan is ProductPlan.ENTERPRISE
    assert snapshot.enforcement_enabled is False


def test_past_due_subscription_has_bounded_grace_period(store):
    service = EntitlementService(store, enforcement_enabled=True)
    recent = _subscription("grace", ProductPlan.WATCH_PLUS, status="past_due")
    store.upsert_tenant_subscription(recent)
    snapshot = service.snapshot("grace")
    assert snapshot.plan is ProductPlan.WATCH_PLUS
    assert snapshot.billing_attention is True

    expired = recent.model_copy(update={"updated_at": utc_now() - timedelta(days=8)})
    store.upsert_tenant_subscription(expired)
    downgraded = service.snapshot("grace")
    assert downgraded.plan is ProductPlan.GATE_FREE
    assert downgraded.billing_attention is True


def test_public_product_split_and_plan_catalogue_are_visible():
    client = TestClient(app)
    landing = client.get("/")
    assert landing.status_code == 200
    assert "Gate Free" in landing.text
    assert "Watch+" in landing.text
    plans = client.get("/v1/billing/plans").json()
    assert [item["id"] for item in plans] == [
        "gate_free",
        "gate",
        "watch",
        "watch_plus",
        "enterprise",
    ]


def test_stripe_webhook_signature_replay_and_subscription_projection(store):
    secret = "whsec_test_secret"
    event = {
        "id": "evt_once",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_123",
                "status": "active",
                "current_period_end": int(time.time()) + 3600,
                "metadata": {
                    "tenant_id": "tenant-paid",
                    "plan": "watch_plus",
                    "extra_agents": "7",
                },
            }
        },
    }
    payload = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    digest = hmac.new(
        secret.encode(), str(timestamp).encode() + b"." + payload, hashlib.sha256
    ).hexdigest()
    verified = StripeWebhookVerifier(secret).verify(
        payload, f"t={timestamp},v1={digest}"
    )
    processor = BillingWebhookProcessor(store)
    assert processor.process(verified) is True
    assert processor.process(verified) is False
    subscription = store.get_tenant_subscription("tenant-paid")
    assert subscription is not None
    assert subscription.plan is ProductPlan.WATCH_PLUS
    assert subscription.extra_agents == 7

    with pytest.raises(BillingError, match="Invalid Stripe webhook signature"):
        StripeWebhookVerifier(secret).verify(payload, f"t={timestamp},v1=bad")


class _FakeResponses:
    def __init__(self, payload):
        self.payload = payload

    def create(self, **kwargs):
        self.kwargs = kwargs
        return type("Response", (), {"output_text": json.dumps(self.payload)})()


class _FakeClient:
    def __init__(self, payload):
        self.responses = _FakeResponses(payload)


def test_llm_watch_analysis_is_evidence_bound_and_advisory(store, principal):
    principal = _watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="semantic-task", description="Review deployment"
        ),
    )
    event, _ = watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            event_type=WatchEventType.TOOL_CALL,
            tool_name="search_knowledge",
        ),
    )
    fake = _FakeClient(
        {
            "risk_found": True,
            "category": "goal-drift",
            "severity": "medium",
            "confidence": 0.72,
            "summary": "The observed tool sequence may not advance the stated goal.",
            "evidence_event_ids": [event.id],
            "recommended_action": "Ask a reviewer to inspect the task goal.",
            "limitations": ["Only one event is available."],
        }
    )
    intelligence = WatchIntelligenceService(
        store,
        api_key="unused",
        model="test-model",
        enabled=True,
        allow_description=False,
        client=fake,
    )
    result = intelligence.analyze(task.task_id, principal.tenant_id)
    assert result.risk_found is True
    assert result.finding_id
    finding = store.get_watch_finding(result.finding_id)
    assert finding.detector_type == "llm"
    plan = store.list_intervention_plans(task_id=task.task_id)[0]
    assert plan.action.value == "review_task"
    assert plan.parameters["automatic_execution_allowed"] is False
    sent = json.loads(fake.responses.kwargs["input"][1]["content"])
    assert sent["task"]["description"] == "[withheld]"
    assert "arguments" not in sent["events"][0]


def test_progress_score_uses_declared_milestones(store, principal):
    principal = _watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="progress-task",
            description="Ship a reviewed change",
            success_criteria=["implemented", "tested", "reviewed"],
        ),
    )
    for milestone in ("implemented", "tested"):
        watch.ingest(
            principal,
            WatchEventRequest(
                task_id=task.task_id,
                event_type=WatchEventType.PROGRESS,
                milestone_id=milestone,
            ),
        )
    progress = watch.progress(task.task_id, principal.tenant_id)
    assert progress.progress_score == pytest.approx(2 / 3)
    assert progress.completed_milestones == ["implemented", "tested"]
    assert progress.missing_milestones == ["reviewed"]
    assert len(progress.evidence_event_ids) == 2


def test_llm_cannot_invent_evidence_ids(store, principal):
    principal = _watch_principal(principal)
    watch = WatchService(store)
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(task_id="forged-evidence", description="Test"),
    )
    fake = _FakeClient(
        {
            "risk_found": True,
            "category": "risk",
            "severity": "high",
            "confidence": 0.9,
            "summary": "Risk",
            "evidence_event_ids": ["fabricated-event"],
            "recommended_action": "Review",
            "limitations": [],
        }
    )
    intelligence = WatchIntelligenceService(
        store,
        api_key="unused",
        model="test-model",
        enabled=True,
        allow_description=False,
        client=fake,
    )
    with pytest.raises(WatchIntelligenceError, match="outside the supplied task"):
        intelligence.analyze(task.task_id, principal.tenant_id)


def test_explicit_deterministic_policy_can_only_pause_task(store, principal):
    principal = _watch_principal(principal)
    store.upsert_tenant_subscription(
        _subscription(principal.tenant_id, ProductPlan.WATCH_PLUS)
    )
    entitlements = EntitlementService(store, enforcement_enabled=True)
    store.upsert_response_policy(
        ResponsePolicy(
            tenant_id=principal.tenant_id,
            finding_code="WATCH_UNEXPECTED_TOOL",
            minimum_confidence=0.99,
            enabled=True,
            updated_by="admin",
            updated_at=utc_now(),
        )
    )
    watch = WatchService(
        store,
        monitor_only=False,
        entitlements=entitlements,
        auto_response_enabled=True,
    )
    task = watch.create_task(
        principal,
        WatchTaskCreateRequest(
            task_id="auto-pause",
            description="Bounded response",
            expected_tools=["search_knowledge"],
        ),
    )
    watch.ingest(
        principal,
        WatchEventRequest(
            task_id=task.task_id,
            event_type=WatchEventType.TOOL_CALL,
            tool_name="send_email",
        ),
    )
    assert store.get_watch_task(task.task_id, principal.tenant_id).status == "paused"
    plan = store.list_intervention_plans(task_id=task.task_id)[0]
    assert plan.status == "executed"
    assert plan.reviewer == "sentinelgate-response-policy"


def test_session_revocation_does_not_revoke_other_agent_tokens(store, principal):
    first = _watch_principal(principal, "session-token")
    second = _watch_principal(principal, "other-token")
    store.register_agent_token(first, "owner")
    store.register_agent_token(second, "owner")
    watch = WatchService(store)
    task = watch.create_task(
        first,
        WatchTaskCreateRequest(task_id="session-bound", description="Session bound"),
    )
    watch.ingest(
        first,
        WatchEventRequest(
            task_id=task.task_id,
            session_id="runtime-a",
            event_type=WatchEventType.HEARTBEAT,
        ),
    )
    respond = RespondService(store, watch)
    assert (
        respond.revoke_session(
            principal.tenant_id,
            task.task_id,
            "runtime-a",
            "approver",
            "Compromised runtime",
        )
        == 1
    )
    assert store.token_is_active(first) is False
    assert store.token_is_active(second) is True
    with pytest.raises(RespondError):
        respond.revoke_session(
            principal.tenant_id,
            task.task_id,
            "runtime-a",
            "approver",
            "Replay",
        )
