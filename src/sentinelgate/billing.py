"""Minimal Stripe-hosted subscription billing boundary.

No card data enters SentinelGate. Checkout and the customer portal are hosted
by Stripe; signed webhooks update the local entitlement projection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from sentinelgate.models import ProductPlan, TenantSubscription, utc_now
from sentinelgate.storage import Store


class BillingError(RuntimeError):
    pass


class StripeWebhookVerifier:
    def __init__(self, secret: str, tolerance_seconds: int = 300):
        self.secret = secret.encode("utf-8")
        self.tolerance_seconds = tolerance_seconds

    def verify(self, payload: bytes, signature_header: str) -> dict[str, Any]:
        timestamp: int | None = None
        signatures: list[str] = []
        for component in signature_header.split(","):
            key, _, value = component.strip().partition("=")
            if key == "t":
                try:
                    timestamp = int(value)
                except ValueError as exc:
                    raise BillingError("Invalid Stripe signature timestamp") from exc
            elif key == "v1" and value:
                signatures.append(value)
        if timestamp is None or not signatures:
            raise BillingError("Stripe signature is incomplete")
        if abs(int(time.time()) - timestamp) > self.tolerance_seconds:
            raise BillingError("Stripe webhook timestamp is outside tolerance")
        signed = str(timestamp).encode() + b"." + payload
        expected = hmac.new(self.secret, signed, hashlib.sha256).hexdigest()
        if not any(hmac.compare_digest(expected, item) for item in signatures):
            raise BillingError("Invalid Stripe webhook signature")
        try:
            event = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise BillingError("Stripe webhook payload is invalid JSON") from exc
        if not isinstance(event, dict) or not isinstance(event.get("id"), str):
            raise BillingError("Stripe webhook event is malformed")
        return event


class StripeBillingClient:
    API_BASE = "https://api.stripe.com/v1"

    def __init__(
        self,
        secret_key: str,
        public_url: str,
        plan_price_ids: dict[ProductPlan, str],
        extra_agent_price_id: str | None = None,
        timeout_seconds: float = 10.0,
    ):
        self.secret_key = secret_key
        self.public_url = public_url.rstrip("/")
        self.plan_price_ids = plan_price_ids
        self.extra_agent_price_id = extra_agent_price_id
        self.timeout_seconds = timeout_seconds

    def _post(self, path: str, data: dict[str, str | int]) -> dict[str, Any]:
        try:
            response = httpx.post(
                f"{self.API_BASE}{path}",
                data=data,
                headers={"Authorization": f"Bearer {self.secret_key}"},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BillingError("Stripe billing request failed") from exc
        if not isinstance(payload, dict):
            raise BillingError("Stripe returned an invalid response")
        return payload

    def create_checkout(
        self,
        *,
        tenant_id: str,
        plan: ProductPlan,
        extra_agents: int,
        customer_email: str | None,
    ) -> str:
        if plan not in {ProductPlan.GATE, ProductPlan.WATCH, ProductPlan.WATCH_PLUS}:
            raise BillingError(
                "This plan is not available through self-service checkout"
            )
        price_id = self.plan_price_ids.get(plan)
        if not price_id:
            raise BillingError("Stripe price is not configured for this plan")
        data: dict[str, str | int] = {
            "mode": "subscription",
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": 1,
            "client_reference_id": tenant_id,
            "success_url": f"{self.public_url}/console/billing?checkout=success",
            "cancel_url": f"{self.public_url}/pricing?checkout=cancelled",
            "metadata[tenant_id]": tenant_id,
            "metadata[plan]": plan.value,
            "metadata[extra_agents]": extra_agents,
            "subscription_data[metadata][tenant_id]": tenant_id,
            "subscription_data[metadata][plan]": plan.value,
            "subscription_data[metadata][extra_agents]": extra_agents,
            "allow_promotion_codes": "true",
        }
        if customer_email:
            data["customer_email"] = customer_email
        if extra_agents:
            if not self.extra_agent_price_id:
                raise BillingError("Additional-agent billing is not configured")
            data.update(
                {
                    "line_items[1][price]": self.extra_agent_price_id,
                    "line_items[1][quantity]": extra_agents,
                }
            )
        payload = self._post("/checkout/sessions", data)
        url = payload.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise BillingError("Stripe checkout URL is missing")
        return url

    def create_portal(self, customer_id: str) -> str:
        payload = self._post(
            "/billing_portal/sessions",
            {
                "customer": customer_id,
                "return_url": f"{self.public_url}/console/billing",
            },
        )
        url = payload.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise BillingError("Stripe portal URL is missing")
        return url


class BillingWebhookProcessor:
    SUPPORTED_EVENTS: ClassVar[set[str]] = {
        "checkout.session.completed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    }

    def __init__(self, store: Store):
        self.store = store

    def process(self, event: dict[str, Any]) -> bool:
        event_id = str(event["id"])
        event_type = str(event.get("type", ""))
        if event_type not in self.SUPPORTED_EVENTS:
            return False
        if not self.store.claim_billing_event(event_id, event_type):
            return False
        try:
            obj = event["data"]["object"]
            if not isinstance(obj, dict):
                raise BillingError("Stripe event object is malformed")
            metadata = obj.get("metadata") or {}
            if not isinstance(metadata, dict):
                raise BillingError("Stripe event metadata is malformed")
            tenant_id = str(
                metadata.get("tenant_id") or obj.get("client_reference_id") or ""
            )
            plan_value = str(metadata.get("plan") or "")
            if not tenant_id or not plan_value:
                raise BillingError("Stripe event is missing SentinelGate metadata")
            try:
                plan = ProductPlan(plan_value)
                extra_agents = int(metadata.get("extra_agents", 0))
            except (ValueError, TypeError) as exc:
                raise BillingError("Stripe event has invalid plan metadata") from exc
            if event_type == "checkout.session.completed":
                status = (
                    "active"
                    if obj.get("payment_status") in {"paid", "no_payment_required"}
                    else "incomplete"
                )
                customer_id = _string_id(obj.get("customer"))
                subscription_id = _string_id(obj.get("subscription"))
                period_end = None
            else:
                status = (
                    "canceled"
                    if event_type.endswith("deleted")
                    else str(obj.get("status", "incomplete"))
                )
                customer_id = _string_id(obj.get("customer"))
                subscription_id = _string_id(obj.get("id"))
                timestamp = obj.get("current_period_end")
                period_end = (
                    datetime.fromtimestamp(int(timestamp), tz=UTC)
                    if timestamp is not None
                    else None
                )
            self.store.upsert_tenant_subscription(
                TenantSubscription(
                    tenant_id=tenant_id,
                    plan=plan,
                    status=status,
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=subscription_id,
                    extra_agents=max(0, extra_agents),
                    current_period_end=period_end,
                    updated_at=utc_now(),
                )
            )
            self.store.complete_billing_event(event_id)
            return True
        except Exception as exc:
            self.store.fail_billing_event(event_id, f"{type(exc).__name__}: {exc}")
            raise


def _string_id(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("id"), str):
        return value["id"]
    return None
