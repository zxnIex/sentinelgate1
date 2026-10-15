"""Shared-SaaS account, organisation and browser-session boundary.

This module deliberately does not turn an OIDC role into global access. In shared
mode, every operator action is authorised against a local tenant membership.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import timedelta
from uuid import uuid4

from sentinelgate.admin_identity import AdminIdentity
from sentinelgate.models import (
    InvitationTokenResponse,
    LegalAcceptanceRequest,
    MembershipRole,
    OperatorAccount,
    OperatorSession,
    Organisation,
    OrganisationCreateRequest,
    TenantInvitation,
    TenantMembership,
    utc_now,
)
from sentinelgate.storage import Store


class SaaSIdentityError(PermissionError):
    pass


ROLE_PERMISSIONS: dict[MembershipRole, frozenset[str]] = {
    MembershipRole.VIEWER: frozenset({"viewer"}),
    MembershipRole.ANALYST: frozenset({"viewer", "analyst"}),
    MembershipRole.APPROVER: frozenset({"viewer", "approver"}),
    MembershipRole.ADMINISTRATOR: frozenset(
        {"viewer", "analyst", "approver", "administrator"}
    ),
    MembershipRole.OWNER: frozenset(
        {"viewer", "analyst", "approver", "administrator", "owner"}
    ),
}


class SaaSIdentityService:
    def __init__(
        self,
        store: Store,
        signing_key: str,
        *,
        terms_version: str,
        privacy_version: str,
        session_hours: int = 8,
    ):
        self.store = store
        self.key = signing_key.encode()
        self.terms_version = terms_version
        self.privacy_version = privacy_version
        self.session_hours = session_hours

    def digest(self, value: str) -> str:
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()

    def sync_account(self, subject: str, email: str | None) -> OperatorAccount:
        existing = self.store.get_operator_account(subject)
        if existing and existing.status != "active":
            raise SaaSIdentityError("Operator account is not active")
        now = utc_now()
        return self.store.upsert_operator_account(
            OperatorAccount(
                subject=subject,
                email=email,
                created_at=existing.created_at if existing else now,
                updated_at=now,
            )
        )

    def create_browser_session(
        self, subject: str, email: str | None
    ) -> tuple[str, OperatorSession]:
        self.sync_account(subject, email)
        raw_token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        session = OperatorSession(
            id=str(uuid4()),
            subject=subject,
            email=email,
            csrf_token=csrf,
            expires_at=utc_now() + timedelta(hours=self.session_hours),
        )
        self.store.create_operator_session(
            session, self.digest(raw_token), self.digest(csrf)
        )
        return raw_token, session

    def resolve_browser_session(
        self, raw_token: str, selected_tenant: str | None
    ) -> AdminIdentity:
        record = self.store.resolve_operator_session(self.digest(raw_token))
        if record is None:
            raise SaaSIdentityError("Operator session is invalid or expired")
        subject, email, session_id, csrf_digest = record
        account = self.store.get_operator_account(subject)
        if account is None or account.status != "active":
            raise SaaSIdentityError("Operator account is not active")
        roles: frozenset[str] = frozenset()
        membership_role = None
        if selected_tenant:
            membership = self.store.get_membership(selected_tenant, subject)
            if membership is None:
                raise SaaSIdentityError("No active membership for selected tenant")
            roles = ROLE_PERMISSIONS[membership.role]
            membership_role = membership.role.value
        return AdminIdentity(
            subject=subject,
            email=email,
            roles=roles,
            tenant_id=selected_tenant,
            membership_role=membership_role,
            session_id=session_id,
            csrf_digest=csrf_digest,
        )

    def verify_csrf(self, identity: AdminIdentity, csrf_token: str) -> bool:
        if not identity.session_id or not identity.csrf_digest or not csrf_token:
            return False
        return hmac.compare_digest(identity.csrf_digest, self.digest(csrf_token))

    def create_organisation(
        self, identity: AdminIdentity, request: OrganisationCreateRequest
    ) -> Organisation:
        self._consume_limit(identity.subject, "create-organisation", 5, 86_400)
        if not self.store.has_legal_acceptance(
            identity.subject, self.terms_version, self.privacy_version
        ):
            raise SaaSIdentityError("Current terms and privacy notice must be accepted")
        slug = request.tenant_id or self._slug(request.name)
        now = utc_now()
        organisation = Organisation(
            tenant_id=slug,
            name=request.name.strip(),
            created_by=identity.subject,
            created_at=now,
            updated_at=now,
        )
        owner = TenantMembership(
            tenant_id=slug,
            subject=identity.subject,
            email=identity.email,
            role=MembershipRole.OWNER,
            created_at=now,
            updated_at=now,
        )
        try:
            return self.store.create_organisation(organisation, owner)
        except Exception as exc:
            raise SaaSIdentityError("Organisation identifier is unavailable") from exc

    def create_invitation(
        self,
        identity: AdminIdentity,
        tenant_id: str,
        email: str,
        role: MembershipRole,
        expires_in_hours: int,
    ) -> InvitationTokenResponse:
        self._consume_limit(identity.subject, "create-invitation", 30, 3_600)
        self.require_membership(
            identity, tenant_id, {MembershipRole.OWNER, MembershipRole.ADMINISTRATOR}
        )
        if role is MembershipRole.OWNER:
            raise SaaSIdentityError(
                "Ownership transfer is a separate protected workflow"
            )
        now = utc_now()
        raw_token = secrets.token_urlsafe(48)
        invitation = TenantInvitation(
            id=str(uuid4()),
            tenant_id=tenant_id,
            email=email.casefold().strip(),
            role=role,
            status="pending",
            created_by=identity.subject,
            created_at=now,
            expires_at=now + timedelta(hours=expires_in_hours),
        )
        self.store.create_invitation(invitation, self.digest(raw_token))
        return InvitationTokenResponse(invitation=invitation, token=raw_token)

    def accept_invitation(
        self, identity: AdminIdentity, raw_token: str
    ) -> TenantMembership:
        self._consume_limit(identity.subject, "accept-invitation", 20, 3_600)
        if not identity.email:
            raise SaaSIdentityError("A verified email claim is required")
        membership = self.store.accept_invitation(
            self.digest(raw_token), identity.subject, identity.email
        )
        if membership is None:
            raise SaaSIdentityError(
                "Invitation is invalid, expired, used, or for another email"
            )
        return membership

    def require_membership(
        self,
        identity: AdminIdentity,
        tenant_id: str,
        allowed: set[MembershipRole] | None = None,
        *,
        allow_deletion_pending: bool = False,
    ) -> TenantMembership:
        membership = self.store.get_membership(
            tenant_id,
            identity.subject,
            allow_deletion_pending=allow_deletion_pending,
        )
        if membership is None:
            raise SaaSIdentityError("No active membership for selected tenant")
        if allowed is not None and membership.role not in allowed:
            raise SaaSIdentityError("Tenant role does not permit this action")
        return membership

    def bind_tenant(
        self, identity: AdminIdentity, tenant_id: str | None
    ) -> AdminIdentity:
        self.sync_account(identity.subject, identity.email)
        if not tenant_id:
            return AdminIdentity(
                subject=identity.subject,
                email=identity.email,
                roles=frozenset(),
            )
        membership = self.require_membership(identity, tenant_id)
        return AdminIdentity(
            subject=identity.subject,
            email=identity.email,
            roles=ROLE_PERMISSIONS[membership.role],
            tenant_id=tenant_id,
            membership_role=membership.role.value,
        )

    def accept_legal(
        self,
        identity: AdminIdentity,
        request: LegalAcceptanceRequest,
        source_ip: str | None,
        user_agent: str | None,
    ) -> None:
        if request.terms_version != self.terms_version:
            raise SaaSIdentityError("Terms version is not current")
        if request.privacy_version != self.privacy_version:
            raise SaaSIdentityError("Privacy notice version is not current")
        self.store.record_legal_acceptance(
            identity.subject,
            request.terms_version,
            request.privacy_version,
            self.digest(source_ip) if source_ip else None,
            self.digest(user_agent) if user_agent else None,
        )

    def _consume_limit(
        self, subject: str, action: str, limit: int, window_seconds: int
    ) -> None:
        if not self.store.account_rate_allowed(subject, action, limit, window_seconds):
            raise SaaSIdentityError(
                f"Too many {action.replace('-', ' ')} attempts; try again later"
            )

    @staticmethod
    def _slug(value: str) -> str:
        base = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")[:80]
        if len(base) < 2:
            base = "organisation"
        return f"{base}-{secrets.token_hex(3)}"
