import base64
import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool
except ImportError:  # pragma: no cover - installation requires the dependency
    psycopg = None
    dict_row = None
    ConnectionPool = None

DATABASE_INTEGRITY_ERRORS = (
    (sqlite3.IntegrityError, psycopg.IntegrityError)
    if psycopg is not None
    else (sqlite3.IntegrityError,)
)

from sentinelgate.models import (
    ActivityEvent,
    AgentPrincipal,
    AgentRecord,
    ApprovalRecord,
    ContainmentMode,
    ContainmentRecord,
    DataClassification,
    Incident,
    InterventionAction,
    InterventionPlan,
    LineageRecord,
    MembershipRole,
    OperatorAccount,
    OperatorSession,
    Organisation,
    OrganisationStatus,
    ProductPlan,
    ResponsePolicy,
    TenantInvitation,
    TenantMembership,
    TenantSubscription,
    ToolCallRequest,
    TraceSummary,
    TrustLevel,
    WatchEventRecord,
    WatchEventRequest,
    WatchFinding,
    WatchFindingAction,
    WatchIntelligenceResult,
    WatchProfile,
    WatchSummary,
    WatchTaskCreateRequest,
    WatchTaskRecord,
    utc_now,
)


class StorageIntegrityError(RuntimeError):
    pass


class _PostgresConnection:
    """Small DB-API compatibility layer for the store's portable SQL subset."""

    def __init__(self, connection: Any):
        self.connection = connection

    @staticmethod
    def _sql(statement: str) -> str:
        if statement.strip().upper() == "BEGIN IMMEDIATE":
            return "BEGIN"
        return statement.replace("LIMIT -1 OFFSET", "OFFSET").replace("?", "%s")

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        return self.connection.execute(self._sql(statement), parameters)

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            if statement.strip():
                self.connection.execute(statement)


class Store:
    def __init__(
        self,
        path: Path | str,
        signing_key: str,
        encryption_key: str,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
    ):
        if len(encryption_key) < 24:
            raise ValueError("Data encryption key must be at least 24 characters")
        database = str(path)
        self._postgres = database.startswith(("postgresql://", "postgresql+psycopg://"))
        self._pool = None
        if self._postgres:
            if ConnectionPool is None:
                raise RuntimeError(
                    "PostgreSQL support requires psycopg and psycopg-pool"
                )
            database = database.replace("postgresql+psycopg://", "postgresql://", 1)
            self._pool = ConnectionPool(
                database,
                min_size=pool_min_size,
                max_size=pool_max_size,
                kwargs={"row_factory": dict_row},
                open=True,
            )
            self.path = None
        else:
            sqlite_path = Path(path)
            sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            self.path = sqlite_path
        self.key = signing_key.encode("utf-8")
        self._cipher = AESGCM(hashlib.sha256(encryption_key.encode("utf-8")).digest())
        self._lock = Lock()
        self._init_schema()

    @property
    def backend(self) -> str:
        return "postgresql" if self._postgres else "sqlite"

    def metadata_fingerprint(self, value: str) -> str:
        """Return a non-reversible, deployment-keyed equality fingerprint."""
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()

    def _transaction_lock(self, db: Any, name: str) -> None:
        if self._postgres:
            db.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",
                (name,),
            )

    @staticmethod
    def _scalar(db: Any, statement: str, parameters: tuple[Any, ...] = ()) -> int:
        row = db.execute(statement, parameters).fetchone()
        return int(next(iter(row.values())) if isinstance(row, dict) else row[0])

    @contextmanager
    def _connect(self) -> Iterator[Any]:
        if self._pool is not None:
            with self._pool.connection() as connection:
                try:
                    yield _PostgresConnection(connection)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
            return
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL,
                    payload TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY, applied_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals_v2 (
                    id TEXT PRIMARY KEY, request_json TEXT NOT NULL, request_hash TEXT NOT NULL,
                    agent_id TEXT NOT NULL, tenant_id TEXT NOT NULL, scopes_json TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    resolved_at TEXT, reviewer TEXT, note TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executions (
                    request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, status TEXT NOT NULL,
                    started_at TEXT NOT NULL, completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS rate_events (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_rate_events_agent_time
                    ON rate_events(tenant_id, agent_id, created_at);
                CREATE TABLE IF NOT EXISTS account_rate_events (
                    subject TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_account_rate_events_subject_time
                    ON account_rate_events(subject, action, created_at);
                CREATE TABLE IF NOT EXISTS violations (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, severity TEXT NOT NULL,
                    reason TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_violations_agent_time
                    ON violations(tenant_id, agent_id, created_at);
                CREATE TABLE IF NOT EXISTS quarantines (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, reason TEXT NOT NULL,
                    created_at TEXT NOT NULL, released_at TEXT, reviewer TEXT, note TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, agent_id)
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL,
                    event_count INTEGER NOT NULL, status TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    UNIQUE(tenant_id, agent_id, trace_id)
                );
                CREATE TABLE IF NOT EXISTS agents (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, owner TEXT NOT NULL,
                    status TEXT NOT NULL, scopes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, agent_id)
                );
                CREATE TABLE IF NOT EXISTS agent_tokens (
                    token_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL, revoked_at TEXT, revoke_reason TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_agent_tokens_agent
                    ON agent_tokens(tenant_id, agent_id, revoked_at);
                CREATE TABLE IF NOT EXISTS containments (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    mode TEXT NOT NULL, reason TEXT NOT NULL, reviewer TEXT NOT NULL,
                    allowed_tools_json TEXT NOT NULL, incident_id TEXT,
                    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, released_at TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_containments_agent
                    ON containments(tenant_id, agent_id, expires_at, released_at);
                CREATE TABLE IF NOT EXISTS egress_events (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_egress_agent_time
                    ON egress_events(tenant_id, agent_id, created_at);
                CREATE TABLE IF NOT EXISTS action_events (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, trace_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL, category TEXT NOT NULL, decision TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_actions_trace_time
                    ON action_events(tenant_id, agent_id, trace_id, created_at);
                CREATE TABLE IF NOT EXISTS lineage_events (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL, request_id TEXT, parent_ids_json TEXT NOT NULL,
                    source_type TEXT NOT NULL, source_id TEXT NOT NULL,
                    destination TEXT NOT NULL, trust TEXT NOT NULL,
                    classification TEXT NOT NULL, labels_json TEXT NOT NULL,
                    content_digest TEXT NOT NULL, created_at TEXT NOT NULL,
                    field_taint_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS ix_lineage_trace_time
                    ON lineage_events(tenant_id, agent_id, trace_id, created_at);
                CREATE TABLE IF NOT EXISTS policy_snapshots (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL, tool_name TEXT NOT NULL,
                    protected_snapshot TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_policy_snapshots_time
                    ON policy_snapshots(created_at);
                CREATE TABLE IF NOT EXISTS mcp_tool_baselines (
                    server_id TEXT NOT NULL, tool_name TEXT NOT NULL,
                    digest TEXT NOT NULL, definition_json TEXT NOT NULL,
                    status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    PRIMARY KEY(server_id, tool_name)
                );
                CREATE INDEX IF NOT EXISTS ix_mcp_tool_name
                    ON mcp_tool_baselines(tool_name);
                CREATE TABLE IF NOT EXISTS mcp_tool_observations (
                    server_id TEXT NOT NULL, tool_name TEXT NOT NULL,
                    digest TEXT NOT NULL, status TEXT NOT NULL,
                    findings_json TEXT NOT NULL, observed_at TEXT NOT NULL,
                    PRIMARY KEY(server_id, tool_name)
                );
                CREATE TABLE IF NOT EXISTS outbox_jobs (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, deduplication_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL, status TEXT NOT NULL,
                    attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL, locked_by TEXT, locked_at TEXT,
                    last_error TEXT, created_at TEXT NOT NULL, completed_at TEXT,
                    UNIQUE(kind, deduplication_key)
                );
                CREATE INDEX IF NOT EXISTS ix_outbox_ready
                    ON outbox_jobs(status, next_attempt_at, created_at);
                CREATE TABLE IF NOT EXISTS worker_heartbeats (
                    worker_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL, processed INTEGER NOT NULL,
                    failed INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watch_tasks (
                    task_id TEXT NOT NULL, workflow_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    description TEXT NOT NULL, profile TEXT NOT NULL,
                    expected_tools_json TEXT NOT NULL, success_criteria_json TEXT NOT NULL,
                    allow_multi_session INTEGER NOT NULL DEFAULT 0,
                    max_runtime_seconds INTEGER NOT NULL, max_tool_calls INTEGER NOT NULL,
                    max_cost_usd REAL NOT NULL, status TEXT NOT NULL,
                    event_count INTEGER NOT NULL, estimated_cost_usd REAL NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT,
                    PRIMARY KEY(tenant_id, task_id)
                );
                CREATE INDEX IF NOT EXISTS ix_watch_tasks_agent_status
                    ON watch_tasks(tenant_id, agent_id, status, updated_at);
                CREATE TABLE IF NOT EXISTS watch_events (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL, schema_version TEXT NOT NULL DEFAULT '1.0',
                    session_id TEXT, event_type TEXT NOT NULL, tool_name TEXT,
                    outcome TEXT, error_code TEXT, call_fingerprint TEXT,
                    progress_signal TEXT, milestone_id TEXT, input_tokens INTEGER NOT NULL,
                    output_tokens INTEGER NOT NULL, estimated_cost_usd REAL NOT NULL,
                    duration_ms REAL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_watch_events_task_time
                    ON watch_events(tenant_id, task_id, created_at);
                CREATE TABLE IF NOT EXISTS watch_findings (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    task_id TEXT NOT NULL, code TEXT NOT NULL, severity TEXT NOT NULL,
                    confidence REAL NOT NULL, summary TEXT NOT NULL,
                    evidence_json TEXT NOT NULL, recommended_action TEXT NOT NULL,
                    status TEXT NOT NULL, occurrences INTEGER NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    resolved_at TEXT, reviewer TEXT, note TEXT NOT NULL,
                    detector_type TEXT NOT NULL DEFAULT 'deterministic', analysis_id TEXT,
                    UNIQUE(tenant_id, task_id, code)
                );
                CREATE INDEX IF NOT EXISTS ix_watch_findings_status_time
                    ON watch_findings(tenant_id, status, last_seen);
                CREATE TABLE IF NOT EXISTS intervention_plans (
                    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
                    action TEXT NOT NULL, rationale TEXT NOT NULL,
                    parameters_json TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, resolved_at TEXT, reviewer TEXT, note TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_intervention_plans_status_time
                    ON intervention_plans(tenant_id, status, created_at);
                CREATE TABLE IF NOT EXISTS tenant_subscriptions (
                    tenant_id TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL,
                    stripe_customer_id TEXT, stripe_subscription_id TEXT,
                    extra_agents INTEGER NOT NULL DEFAULT 0, current_period_end TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ix_subscription_customer
                    ON tenant_subscriptions(stripe_customer_id);
                CREATE TABLE IF NOT EXISTS billing_events (
                    event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
                    status TEXT NOT NULL, error TEXT, received_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS watch_intelligence_analyses (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    task_id TEXT NOT NULL, model TEXT NOT NULL, prompt_version TEXT NOT NULL,
                    input_digest TEXT NOT NULL, result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_watch_intelligence_tenant_time
                    ON watch_intelligence_analyses(tenant_id, created_at);
                CREATE TABLE IF NOT EXISTS watch_session_credentials (
                    tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
                    session_id TEXT NOT NULL, token_id TEXT NOT NULL, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, task_id, session_id, token_id)
                );
                CREATE TABLE IF NOT EXISTS response_policies (
                    tenant_id TEXT NOT NULL, finding_code TEXT NOT NULL,
                    action TEXT NOT NULL, minimum_confidence REAL NOT NULL,
                    deterministic_only INTEGER NOT NULL, enabled INTEGER NOT NULL,
                    updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, finding_code)
                );
                CREATE TABLE IF NOT EXISTS operator_accounts (
                    subject TEXT PRIMARY KEY, email TEXT, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS organisations (
                    tenant_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
                    created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_memberships (
                    tenant_id TEXT NOT NULL, subject TEXT NOT NULL, email TEXT,
                    role TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, subject)
                );
                CREATE INDEX IF NOT EXISTS ix_membership_subject
                    ON tenant_memberships(subject, status, tenant_id);
                CREATE TABLE IF NOT EXISTS tenant_invitations (
                    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL,
                    role TEXT NOT NULL, token_digest TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL, created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    accepted_at TEXT, accepted_by TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_invitation_tenant_status
                    ON tenant_invitations(tenant_id, status, expires_at);
                CREATE TABLE IF NOT EXISTS operator_sessions (
                    id TEXT PRIMARY KEY, subject TEXT NOT NULL, email TEXT,
                    token_digest TEXT NOT NULL UNIQUE, csrf_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL, revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_operator_session_subject
                    ON operator_sessions(subject, expires_at, revoked_at);
                CREATE TABLE IF NOT EXISTS legal_acceptances (
                    id TEXT PRIMARY KEY, subject TEXT NOT NULL,
                    terms_version TEXT NOT NULL, privacy_version TEXT NOT NULL,
                    accepted_at TEXT NOT NULL, source_ip_digest TEXT,
                    user_agent_digest TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_legal_acceptance_subject
                    ON legal_acceptances(subject, accepted_at);
                CREATE TABLE IF NOT EXISTS tenant_deletion_requests (
                    tenant_id TEXT PRIMARY KEY, requested_by TEXT NOT NULL,
                    reason TEXT NOT NULL, status TEXT NOT NULL,
                    requested_at TEXT NOT NULL, execute_after TEXT NOT NULL,
                    cancelled_at TEXT, completed_at TEXT
                );
                """
            )
            if self._postgres:

                def table_columns(table: str) -> set[str]:
                    return {
                        row["column_name"]
                        for row in db.execute(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema='public' AND table_name=?",
                            (table,),
                        ).fetchall()
                    }

                lineage_columns = table_columns("lineage_events")
            else:

                def table_columns(table: str) -> set[str]:
                    return {
                        row["name"] for row in db.execute(f"PRAGMA table_info({table})")
                    }

                lineage_columns = table_columns("lineage_events")
            if "field_taint_json" not in lineage_columns:
                db.execute(
                    "ALTER TABLE lineage_events ADD COLUMN field_taint_json "
                    "TEXT NOT NULL DEFAULT '{}'"
                )
            task_columns = table_columns("watch_tasks")
            if "allow_multi_session" not in task_columns:
                db.execute(
                    "ALTER TABLE watch_tasks ADD COLUMN allow_multi_session "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            if "workflow_id" not in task_columns:
                db.execute(
                    "ALTER TABLE watch_tasks ADD COLUMN workflow_id TEXT NOT NULL DEFAULT ''"
                )
                db.execute(
                    "UPDATE watch_tasks SET workflow_id=task_id WHERE workflow_id='' "
                )
            event_columns = table_columns("watch_events")
            for column, definition in (
                ("schema_version", "TEXT NOT NULL DEFAULT '1.0'"),
                ("session_id", "TEXT"),
                ("milestone_id", "TEXT"),
            ):
                if column not in event_columns:
                    db.execute(
                        f"ALTER TABLE watch_events ADD COLUMN {column} {definition}"
                    )
            finding_columns = table_columns("watch_findings")
            if "detector_type" not in finding_columns:
                db.execute(
                    "ALTER TABLE watch_findings ADD COLUMN detector_type "
                    "TEXT NOT NULL DEFAULT 'deterministic'"
                )
            if "analysis_id" not in finding_columns:
                db.execute("ALTER TABLE watch_findings ADD COLUMN analysis_id TEXT")
            for version in (
                "0001_initial",
                "0002_field_taint",
                "0003_durable_outbox",
                "0004_watch_alpha",
                "0005_watch_beta_schema",
                "0006_bounded_response",
                "0007_multi_agent_workflows",
                "0008_commercial_entitlements",
                "0009_watch_intelligence",
                "0010_bounded_auto_response",
                "0011_saas_accounts_and_tenant_boundary",
                "0012_account_abuse_controls",
            ):
                db.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?) ON CONFLICT DO NOTHING",
                    (version, utc_now().isoformat()),
                )

    def create_watch_task(
        self,
        principal: AgentPrincipal,
        request: WatchTaskCreateRequest,
        audit: bool = True,
    ) -> WatchTaskRecord:
        del audit  # Audit policy is owned by WatchService, not persistence.
        now = utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                """INSERT INTO watch_tasks (
                       task_id, workflow_id, tenant_id, agent_id, description, profile,
                       expected_tools_json, success_criteria_json, allow_multi_session,
                       max_runtime_seconds, max_tool_calls, max_cost_usd,
                       status, event_count, estimated_cost_usd,
                       created_at, updated_at, completed_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, 0, ?, ?, NULL)
                   ON CONFLICT(tenant_id, task_id) DO NOTHING""",
                (
                    request.task_id,
                    request.workflow_id or request.task_id,
                    principal.tenant_id,
                    principal.agent_id,
                    request.description,
                    request.profile.value,
                    json.dumps(sorted(set(request.expected_tools))),
                    json.dumps(request.success_criteria),
                    int(request.allow_multi_session),
                    request.max_runtime_seconds,
                    request.max_tool_calls,
                    request.max_cost_usd,
                    now,
                    now,
                ),
            )
            row = db.execute(
                """SELECT * FROM watch_tasks
                   WHERE tenant_id=? AND task_id=? AND agent_id=?""",
                (principal.tenant_id, request.task_id, principal.agent_id),
            ).fetchone()
        if row is None:
            raise ValueError("Watch task identifier is already owned by another agent")
        return self._watch_task_from_row(row)

    def get_watch_task(
        self, task_id: str, tenant_id: str, agent_id: str | None = None
    ) -> WatchTaskRecord | None:
        query = "SELECT * FROM watch_tasks WHERE tenant_id=? AND task_id=?"
        params: list[Any] = [tenant_id, task_id]
        if agent_id:
            query += " AND agent_id=?"
            params.append(agent_id)
        with self._connect() as db:
            row = db.execute(query, tuple(params)).fetchone()
        return self._watch_task_from_row(row) if row else None

    def list_watch_tasks(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        status: str | None = None,
        workflow_id: str | None = None,
    ) -> list[WatchTaskRecord]:
        filters: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("tenant_id", tenant_id),
            ("agent_id", agent_id),
            ("status", status),
            ("workflow_id", workflow_id),
        ):
            if value:
                filters.append(f"{column}=?")
                params.append(value)
        query = "SELECT * FROM watch_tasks"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(query, tuple(params)).fetchall()
        return [self._watch_task_from_row(row) for row in rows]

    def record_watch_event(
        self, principal: AgentPrincipal, request: WatchEventRequest
    ) -> WatchEventRecord:
        task = self.get_watch_task(
            request.task_id, principal.tenant_id, principal.agent_id
        )
        if task is None:
            raise ValueError("Watch task not found for this agent identity")
        event = WatchEventRecord(
            id=str(uuid4()),
            tenant_id=principal.tenant_id,
            agent_id=principal.agent_id,
            created_at=utc_now(),
            **request.model_dump(),
        )
        terminal = (
            event.outcome
            if event.event_type.value == "task_status"
            and event.outcome in {"completed", "failed", "cancelled"}
            else None
        )
        with self._connect() as db:
            db.execute(
                """INSERT INTO watch_events (
                       id, task_id, tenant_id, agent_id, schema_version, session_id,
                       event_type, tool_name, outcome, error_code, call_fingerprint,
                       progress_signal, milestone_id, input_tokens, output_tokens,
                       estimated_cost_usd, duration_ms, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.id,
                    event.task_id,
                    event.tenant_id,
                    event.agent_id,
                    event.schema_version,
                    event.session_id,
                    event.event_type.value,
                    event.tool_name,
                    event.outcome,
                    event.error_code,
                    event.call_fingerprint,
                    event.progress_signal,
                    event.milestone_id,
                    event.input_tokens,
                    event.output_tokens,
                    event.estimated_cost_usd,
                    event.duration_ms,
                    event.created_at.isoformat(),
                ),
            )
            db.execute(
                """UPDATE watch_tasks SET event_count=event_count+1,
                       estimated_cost_usd=estimated_cost_usd+?, updated_at=?,
                       status=COALESCE(?, status),
                       completed_at=CASE WHEN ? IS NULL THEN completed_at ELSE ? END
                   WHERE tenant_id=? AND agent_id=? AND task_id=?""",
                (
                    event.estimated_cost_usd,
                    event.created_at.isoformat(),
                    terminal,
                    terminal,
                    event.created_at.isoformat(),
                    event.tenant_id,
                    event.agent_id,
                    event.task_id,
                ),
            )
            if event.session_id:
                db.execute(
                    """INSERT INTO watch_session_credentials (
                           tenant_id, agent_id, task_id, session_id, token_id,
                           first_seen, last_seen
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(tenant_id, task_id, session_id, token_id)
                       DO UPDATE SET last_seen=excluded.last_seen""",
                    (
                        event.tenant_id,
                        event.agent_id,
                        event.task_id,
                        event.session_id,
                        principal.token_id,
                        event.created_at.isoformat(),
                        event.created_at.isoformat(),
                    ),
                )
        return event

    def list_watch_events(
        self,
        task_id: str,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 500,
    ) -> list[WatchEventRecord]:
        if tenant_id and agent_id:
            query = (
                "SELECT * FROM watch_events WHERE task_id=? AND tenant_id=? "
                "AND agent_id=? ORDER BY created_at DESC, id DESC LIMIT ?"
            )
            params = (task_id, tenant_id, agent_id, limit)
        elif tenant_id:
            query = (
                "SELECT * FROM watch_events WHERE task_id=? AND tenant_id=? "
                "ORDER BY created_at DESC, id DESC LIMIT ?"
            )
            params = (task_id, tenant_id, limit)
        elif agent_id:
            query = (
                "SELECT * FROM watch_events WHERE task_id=? AND agent_id=? "
                "ORDER BY created_at DESC, id DESC LIMIT ?"
            )
            params = (task_id, agent_id, limit)
        else:
            query = (
                "SELECT * FROM watch_events WHERE task_id=? "
                "ORDER BY created_at DESC, id DESC LIMIT ?"
            )
            params = (task_id, limit)
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return [WatchEventRecord(**dict(row)) for row in rows]

    def upsert_watch_finding(self, finding: WatchFinding) -> WatchFinding:
        now = utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                """INSERT INTO watch_findings (
                       id, tenant_id, agent_id, task_id, code, severity, confidence,
                       summary, evidence_json, recommended_action, status, occurrences,
                       first_seen, last_seen, resolved_at, reviewer, note,
                       detector_type, analysis_id
                   ) VALUES (
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?, NULL, NULL, '', ?, ?
                   ) ON CONFLICT(id) DO UPDATE SET
                       severity=excluded.severity,
                       confidence=excluded.confidence,
                       summary=excluded.summary,
                       evidence_json=excluded.evidence_json,
                       recommended_action=excluded.recommended_action,
                       status='open', occurrences=watch_findings.occurrences+1,
                       last_seen=excluded.last_seen, resolved_at=NULL,
                       detector_type=excluded.detector_type,
                       analysis_id=excluded.analysis_id""",
                (
                    finding.id,
                    finding.tenant_id,
                    finding.agent_id,
                    finding.task_id,
                    finding.code,
                    finding.severity,
                    finding.confidence,
                    finding.summary,
                    json.dumps(finding.evidence),
                    finding.recommended_action,
                    finding.first_seen.isoformat(),
                    now,
                    finding.detector_type,
                    finding.analysis_id,
                ),
            )
            row = db.execute(
                "SELECT * FROM watch_findings WHERE id=?", (finding.id,)
            ).fetchone()
        return self._watch_finding_from_row(row)

    def list_watch_findings(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[WatchFinding]:
        filters: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("tenant_id", tenant_id),
            ("agent_id", agent_id),
            ("task_id", task_id),
            ("status", status),
        ):
            if value:
                filters.append(f"{column}=?")
                params.append(value)
        query = "SELECT * FROM watch_findings"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(query, tuple(params)).fetchall()
        return [self._watch_finding_from_row(row) for row in rows]

    def update_watch_finding(
        self,
        finding_id: str,
        action: WatchFindingAction,
        reviewer: str,
    ) -> WatchFinding | None:
        resolved = utc_now().isoformat() if action.status == "resolved" else None
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE watch_findings SET status=?, resolved_at=?, reviewer=?, note=?
                   WHERE id=?""",
                (action.status, resolved, reviewer, action.note, finding_id),
            )
            row = db.execute(
                "SELECT * FROM watch_findings WHERE id=?", (finding_id,)
            ).fetchone()
        return (
            self._watch_finding_from_row(row) if cursor.rowcount == 1 and row else None
        )

    def get_watch_finding(self, finding_id: str) -> WatchFinding | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM watch_findings WHERE id=?", (finding_id,)
            ).fetchone()
        return self._watch_finding_from_row(row) if row else None

    def update_watch_task_status(
        self, tenant_id: str, task_id: str, status: str
    ) -> WatchTaskRecord | None:
        if status not in {"active", "paused", "completed", "failed", "cancelled"}:
            raise ValueError("Unsupported Watch task status")
        now = utc_now().isoformat()
        terminal = now if status in {"completed", "failed", "cancelled"} else None
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE watch_tasks SET status=?, updated_at=?,
                       completed_at=COALESCE(?, completed_at)
                   WHERE tenant_id=? AND task_id=?""",
                (status, now, terminal, tenant_id, task_id),
            )
            row = db.execute(
                "SELECT * FROM watch_tasks WHERE tenant_id=? AND task_id=?",
                (tenant_id, task_id),
            ).fetchone()
        return self._watch_task_from_row(row) if cursor.rowcount == 1 and row else None

    def create_intervention_plan(
        self,
        finding: WatchFinding,
        action: InterventionAction,
        rationale: str,
        parameters: dict[str, Any],
    ) -> InterventionPlan:
        now = utc_now()
        plan = InterventionPlan(
            id=str(uuid4()),
            finding_id=finding.id,
            tenant_id=finding.tenant_id,
            agent_id=finding.agent_id,
            task_id=finding.task_id,
            action=action,
            rationale=rationale,
            parameters=parameters,
            status="proposed",
            created_at=now,
        )
        with self._connect() as db:
            db.execute(
                """INSERT INTO intervention_plans (
                       id, finding_id, tenant_id, agent_id, task_id, action,
                       rationale, parameters_json, status, created_at,
                       resolved_at, reviewer, note
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, NULL, NULL, '')
                   ON CONFLICT(finding_id) DO NOTHING""",
                (
                    plan.id,
                    plan.finding_id,
                    plan.tenant_id,
                    plan.agent_id,
                    plan.task_id,
                    plan.action.value,
                    plan.rationale,
                    json.dumps(plan.parameters),
                    plan.created_at.isoformat(),
                ),
            )
            row = db.execute(
                "SELECT * FROM intervention_plans WHERE finding_id=?",
                (finding.id,),
            ).fetchone()
        return self._intervention_from_row(row)

    def get_intervention_plan(self, plan_id: str) -> InterventionPlan | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM intervention_plans WHERE id=?", (plan_id,)
            ).fetchone()
        return self._intervention_from_row(row) if row else None

    def list_intervention_plans(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        task_id: str | None = None,
        status: str | None = None,
    ) -> list[InterventionPlan]:
        filters: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("tenant_id", tenant_id),
            ("task_id", task_id),
            ("status", status),
        ):
            if value:
                filters.append(f"{column}=?")
                params.append(value)
        query = "SELECT * FROM intervention_plans"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(query, tuple(params)).fetchall()
        return [self._intervention_from_row(row) for row in rows]

    def resolve_intervention_plan(
        self, plan_id: str, status: str, reviewer: str, note: str
    ) -> InterventionPlan | None:
        if status not in {"approved", "rejected", "executed"}:
            raise ValueError("Unsupported intervention status")
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"intervention:{plan_id}")
            row = db.execute(
                "SELECT * FROM intervention_plans WHERE id=?", (plan_id,)
            ).fetchone()
            if not row or row["status"] != "proposed":
                return None
            db.execute(
                """UPDATE intervention_plans SET status=?, resolved_at=?,
                       reviewer=?, note=? WHERE id=? AND status='proposed'""",
                (status, utc_now().isoformat(), reviewer, note, plan_id),
            )
            updated = db.execute(
                "SELECT * FROM intervention_plans WHERE id=?", (plan_id,)
            ).fetchone()
        return self._intervention_from_row(updated) if updated else None

    def mark_intervention_executed(
        self, plan_id: str, reviewer: str, note: str
    ) -> InterventionPlan | None:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"intervention:{plan_id}")
            cursor = db.execute(
                """UPDATE intervention_plans SET status='executed', resolved_at=?,
                       reviewer=?, note=? WHERE id=? AND status='executing'""",
                (utc_now().isoformat(), reviewer, note, plan_id),
            )
            row = db.execute(
                "SELECT * FROM intervention_plans WHERE id=?", (plan_id,)
            ).fetchone()
        return (
            self._intervention_from_row(row) if cursor.rowcount == 1 and row else None
        )

    def claim_intervention_execution(
        self, plan_id: str, reviewer: str
    ) -> InterventionPlan | None:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"intervention:{plan_id}")
            cursor = db.execute(
                """UPDATE intervention_plans SET status='executing', reviewer=?
                   WHERE id=? AND status='approved'""",
                (reviewer, plan_id),
            )
            row = db.execute(
                "SELECT * FROM intervention_plans WHERE id=?", (plan_id,)
            ).fetchone()
        return (
            self._intervention_from_row(row) if cursor.rowcount == 1 and row else None
        )

    def fail_intervention_execution(
        self, plan_id: str, reviewer: str, note: str
    ) -> InterventionPlan | None:
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE intervention_plans SET status='failed', resolved_at=?,
                       reviewer=?, note=? WHERE id=? AND status='executing'""",
                (utc_now().isoformat(), reviewer, note, plan_id),
            )
            row = db.execute(
                "SELECT * FROM intervention_plans WHERE id=?", (plan_id,)
            ).fetchone()
        return (
            self._intervention_from_row(row) if cursor.rowcount == 1 and row else None
        )

    def watch_summary(self, tenant_id: str | None = None) -> WatchSummary:
        with self._connect() as db:
            if tenant_id:
                params = (tenant_id,)
                active_tasks = self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_tasks "
                    "WHERE status='active' AND tenant_id=?",
                    params,
                )
                open_findings = self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_findings "
                    "WHERE status='open' AND tenant_id=?",
                    params,
                )
                high_risk_findings = self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_findings WHERE status='open' "
                    "AND severity IN ('high','critical') AND tenant_id=?",
                    params,
                )
                monitored_events = self._scalar(
                    db, "SELECT COUNT(*) FROM watch_events WHERE tenant_id=?", params
                )
                cost_query = (
                    "SELECT COALESCE(SUM(estimated_cost_usd),0) AS total "
                    "FROM watch_tasks WHERE tenant_id=?"
                )
            else:
                params = ()
                active_tasks = self._scalar(
                    db, "SELECT COUNT(*) FROM watch_tasks WHERE status='active'"
                )
                open_findings = self._scalar(
                    db, "SELECT COUNT(*) FROM watch_findings WHERE status='open'"
                )
                high_risk_findings = self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_findings WHERE status='open' "
                    "AND severity IN ('high','critical')",
                )
                monitored_events = self._scalar(db, "SELECT COUNT(*) FROM watch_events")
                cost_query = (
                    "SELECT COALESCE(SUM(estimated_cost_usd),0) AS total "
                    "FROM watch_tasks"
                )
            return WatchSummary(
                active_tasks=active_tasks,
                open_findings=open_findings,
                high_risk_findings=high_risk_findings,
                monitored_events=monitored_events,
                estimated_cost_usd=float(
                    db.execute(cost_query, params).fetchone()["total"]
                ),
            )

    def agent_is_active(self, tenant_id: str, agent_id: str) -> bool:
        with self._connect() as db:
            row = db.execute(
                "SELECT 1 FROM agents WHERE tenant_id=? AND agent_id=? AND status='active'",
                (tenant_id, agent_id),
            ).fetchone()
        return row is not None

    def tenant_usage(self, tenant_id: str) -> dict[str, int]:
        month_start = (
            utc_now()
            .replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            .isoformat()
        )
        with self._connect() as db:
            return {
                "agents": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM agents WHERE tenant_id=? AND status='active'",
                    (tenant_id,),
                ),
                "decisions_month": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM action_events WHERE tenant_id=? AND created_at>=?",
                    (tenant_id, month_start),
                ),
                "watch_events_month": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_events WHERE tenant_id=? AND created_at>=?",
                    (tenant_id, month_start),
                ),
                "llm_analyses_month": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_intelligence_analyses "
                    "WHERE tenant_id=? AND created_at>=?",
                    (tenant_id, month_start),
                ),
            }

    def upsert_tenant_subscription(self, record: TenantSubscription) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO tenant_subscriptions (
                       tenant_id, plan, status, stripe_customer_id,
                       stripe_subscription_id, extra_agents, current_period_end,
                       updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id) DO UPDATE SET
                       plan=excluded.plan, status=excluded.status,
                       stripe_customer_id=COALESCE(excluded.stripe_customer_id,
                                                   tenant_subscriptions.stripe_customer_id),
                       stripe_subscription_id=COALESCE(excluded.stripe_subscription_id,
                                                       tenant_subscriptions.stripe_subscription_id),
                       extra_agents=excluded.extra_agents,
                       current_period_end=excluded.current_period_end,
                       updated_at=excluded.updated_at""",
                (
                    record.tenant_id,
                    record.plan.value,
                    record.status,
                    record.stripe_customer_id,
                    record.stripe_subscription_id,
                    record.extra_agents,
                    record.current_period_end.isoformat()
                    if record.current_period_end
                    else None,
                    record.updated_at.isoformat(),
                ),
            )

    def get_tenant_subscription(self, tenant_id: str) -> TenantSubscription | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM tenant_subscriptions WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        if row is None:
            return None
        return TenantSubscription(
            tenant_id=row["tenant_id"],
            plan=ProductPlan(row["plan"]),
            status=row["status"],
            stripe_customer_id=row["stripe_customer_id"],
            stripe_subscription_id=row["stripe_subscription_id"],
            extra_agents=row["extra_agents"],
            current_period_end=(
                datetime.fromisoformat(row["current_period_end"])
                if row["current_period_end"]
                else None
            ),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def claim_billing_event(self, event_id: str, event_type: str) -> bool:
        now = utc_now().isoformat()
        stale_before = (utc_now() - timedelta(minutes=10)).isoformat()
        with self._connect() as db:
            cursor = db.execute(
                """INSERT INTO billing_events (
                       event_id, event_type, status, error, received_at, completed_at
                   ) VALUES (?, ?, 'processing', NULL, ?, NULL)
                   ON CONFLICT(event_id) DO NOTHING""",
                (event_id, event_type, now),
            )
            if cursor.rowcount == 1:
                return True
            retry = db.execute(
                """UPDATE billing_events SET status='processing', error=NULL,
                       received_at=?, completed_at=NULL
                   WHERE event_id=? AND (
                       status='failed' OR
                       (status='processing' AND received_at < ?)
                   )""",
                (now, event_id, stale_before),
            )
            return retry.rowcount == 1

    def complete_billing_event(self, event_id: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE billing_events SET status='completed', completed_at=? WHERE event_id=?",
                (utc_now().isoformat(), event_id),
            )

    def fail_billing_event(self, event_id: str, error: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE billing_events SET status='failed', error=? WHERE event_id=?",
                (error[:1000], event_id),
            )

    def upsert_operator_account(self, account: OperatorAccount) -> OperatorAccount:
        with self._connect() as db:
            db.execute(
                """INSERT INTO operator_accounts (
                       subject, email, status, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(subject) DO UPDATE SET
                       email=COALESCE(excluded.email, operator_accounts.email),
                       updated_at=excluded.updated_at""",
                (
                    account.subject,
                    account.email,
                    account.status,
                    account.created_at.isoformat(),
                    account.updated_at.isoformat(),
                ),
            )
        return self.get_operator_account(account.subject) or account

    def get_operator_account(self, subject: str) -> OperatorAccount | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM operator_accounts WHERE subject=?", (subject,)
            ).fetchone()
        if row is None:
            return None
        return OperatorAccount(
            subject=row["subject"],
            email=row["email"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def create_organisation(
        self, organisation: Organisation, owner: TenantMembership
    ) -> Organisation:
        with self._connect() as db:
            db.execute(
                """INSERT INTO organisations (
                       tenant_id, name, status, created_by, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    organisation.tenant_id,
                    organisation.name,
                    organisation.status.value,
                    organisation.created_by,
                    organisation.created_at.isoformat(),
                    organisation.updated_at.isoformat(),
                ),
            )
            db.execute(
                """INSERT INTO tenant_memberships (
                       tenant_id, subject, email, role, status, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    owner.tenant_id,
                    owner.subject,
                    owner.email,
                    owner.role.value,
                    owner.status,
                    owner.created_at.isoformat(),
                    owner.updated_at.isoformat(),
                ),
            )
        return organisation

    def get_organisation(self, tenant_id: str) -> Organisation | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM organisations WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        if row is None:
            return None
        return Organisation(
            tenant_id=row["tenant_id"],
            name=row["name"],
            status=OrganisationStatus(row["status"]),
            created_by=row["created_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_memberships(self, subject: str) -> list[TenantMembership]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT m.* FROM tenant_memberships m
                   JOIN organisations o ON o.tenant_id=m.tenant_id
                   WHERE m.subject=? AND m.status='active' AND o.status='active'
                   ORDER BY m.created_at""",
                (subject,),
            ).fetchall()
        return [self._membership(row) for row in rows]

    def get_membership(
        self, tenant_id: str, subject: str, *, allow_deletion_pending: bool = False
    ) -> TenantMembership | None:
        with self._connect() as db:
            if allow_deletion_pending:
                row = db.execute(
                    """SELECT m.* FROM tenant_memberships m
                       JOIN organisations o ON o.tenant_id=m.tenant_id
                       WHERE m.tenant_id=? AND m.subject=? AND m.status='active'
                         AND o.status IN ('active','deletion_pending')""",
                    (tenant_id, subject),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT m.* FROM tenant_memberships m
                       JOIN organisations o ON o.tenant_id=m.tenant_id
                       WHERE m.tenant_id=? AND m.subject=? AND m.status='active'
                         AND o.status='active'""",
                    (tenant_id, subject),
                ).fetchone()
        return self._membership(row) if row is not None else None

    def upsert_membership(self, membership: TenantMembership) -> TenantMembership:
        with self._connect() as db:
            db.execute(
                """INSERT INTO tenant_memberships (
                       tenant_id, subject, email, role, status, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, subject) DO UPDATE SET
                       email=COALESCE(excluded.email, tenant_memberships.email),
                       role=excluded.role, status=excluded.status,
                       updated_at=excluded.updated_at""",
                (
                    membership.tenant_id,
                    membership.subject,
                    membership.email,
                    membership.role.value,
                    membership.status,
                    membership.created_at.isoformat(),
                    membership.updated_at.isoformat(),
                ),
            )
        return membership

    def create_invitation(
        self, invitation: TenantInvitation, token_digest: str
    ) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO tenant_invitations (
                       id, tenant_id, email, role, token_digest, status,
                       created_by, created_at, expires_at, accepted_at, accepted_by
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    invitation.id,
                    invitation.tenant_id,
                    invitation.email.casefold(),
                    invitation.role.value,
                    token_digest,
                    invitation.status,
                    invitation.created_by,
                    invitation.created_at.isoformat(),
                    invitation.expires_at.isoformat(),
                ),
            )

    def accept_invitation(
        self, token_digest: str, subject: str, email: str
    ) -> TenantMembership | None:
        now = utc_now()
        with self._connect() as db:
            self._transaction_lock(db, f"invitation:{token_digest}")
            row = db.execute(
                """SELECT * FROM tenant_invitations
                   WHERE token_digest=? AND status='pending' AND expires_at>?""",
                (token_digest, now.isoformat()),
            ).fetchone()
            if row is None or row["email"].casefold() != email.casefold():
                return None
            changed = db.execute(
                """UPDATE tenant_invitations SET status='accepted',
                       accepted_at=?, accepted_by=?
                   WHERE id=? AND status='pending'""",
                (now.isoformat(), subject, row["id"]),
            )
            if changed.rowcount != 1:
                return None
            membership = TenantMembership(
                tenant_id=row["tenant_id"],
                subject=subject,
                email=email,
                role=MembershipRole(row["role"]),
                created_at=now,
                updated_at=now,
            )
            db.execute(
                """INSERT INTO tenant_memberships (
                       tenant_id, subject, email, role, status, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, 'active', ?, ?)
                   ON CONFLICT(tenant_id, subject) DO UPDATE SET
                       email=excluded.email, role=excluded.role, status='active',
                       updated_at=excluded.updated_at""",
                (
                    membership.tenant_id,
                    subject,
                    email,
                    membership.role.value,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
            return membership

    def create_operator_session(
        self, session: OperatorSession, token_digest: str, csrf_digest: str
    ) -> None:
        now = utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                """INSERT INTO operator_sessions (
                       id, subject, email, token_digest, csrf_digest,
                       created_at, expires_at, last_seen_at, revoked_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    session.id,
                    session.subject,
                    session.email,
                    token_digest,
                    csrf_digest,
                    now,
                    session.expires_at.isoformat(),
                    now,
                ),
            )

    def resolve_operator_session(
        self, token_digest: str
    ) -> tuple[str, str | None, str, str] | None:
        now = utc_now().isoformat()
        with self._connect() as db:
            row = db.execute(
                """SELECT * FROM operator_sessions
                   WHERE token_digest=? AND revoked_at IS NULL AND expires_at>?""",
                (token_digest, now),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE operator_sessions SET last_seen_at=? WHERE id=?",
                (now, row["id"]),
            )
        return row["subject"], row["email"], row["id"], row["csrf_digest"]

    def revoke_operator_session(self, session_id: str) -> bool:
        with self._connect() as db:
            changed = db.execute(
                """UPDATE operator_sessions SET revoked_at=?
                   WHERE id=? AND revoked_at IS NULL""",
                (utc_now().isoformat(), session_id),
            )
        return changed.rowcount == 1

    def deactivate_operator_account(self, subject: str) -> bool:
        now = utc_now().isoformat()
        with self._connect() as db:
            owner = db.execute(
                """SELECT 1 FROM tenant_memberships
                   WHERE subject=? AND role='owner' AND status='active' LIMIT 1""",
                (subject,),
            ).fetchone()
            if owner is not None:
                return False
            changed = db.execute(
                """UPDATE operator_accounts SET status='deleted', updated_at=?
                   WHERE subject=? AND status='active'""",
                (now, subject),
            )
            db.execute(
                """UPDATE tenant_memberships SET status='suspended', updated_at=?
                   WHERE subject=? AND status='active'""",
                (now, subject),
            )
            db.execute(
                """UPDATE operator_sessions SET revoked_at=?
                   WHERE subject=? AND revoked_at IS NULL""",
                (now, subject),
            )
        return changed.rowcount == 1

    def record_legal_acceptance(
        self,
        subject: str,
        terms_version: str,
        privacy_version: str,
        source_ip_digest: str | None,
        user_agent_digest: str | None,
    ) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO legal_acceptances (
                       id, subject, terms_version, privacy_version, accepted_at,
                       source_ip_digest, user_agent_digest
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid4()),
                    subject,
                    terms_version,
                    privacy_version,
                    utc_now().isoformat(),
                    source_ip_digest,
                    user_agent_digest,
                ),
            )

    def has_legal_acceptance(
        self, subject: str, terms_version: str, privacy_version: str
    ) -> bool:
        with self._connect() as db:
            row = db.execute(
                """SELECT 1 FROM legal_acceptances
                   WHERE subject=? AND terms_version=? AND privacy_version=?
                   LIMIT 1""",
                (subject, terms_version, privacy_version),
            ).fetchone()
        return row is not None

    def schedule_tenant_deletion(
        self,
        tenant_id: str,
        subject: str,
        reason: str,
        execute_after: datetime,
    ) -> None:
        now = utc_now()
        with self._connect() as db:
            db.execute(
                """INSERT INTO tenant_deletion_requests (
                       tenant_id, requested_by, reason, status, requested_at,
                       execute_after, cancelled_at, completed_at
                   ) VALUES (?, ?, ?, 'pending', ?, ?, NULL, NULL)
                   ON CONFLICT(tenant_id) DO UPDATE SET
                       requested_by=excluded.requested_by, reason=excluded.reason,
                       status='pending', requested_at=excluded.requested_at,
                       execute_after=excluded.execute_after, cancelled_at=NULL,
                       completed_at=NULL""",
                (
                    tenant_id,
                    subject,
                    reason,
                    now.isoformat(),
                    execute_after.isoformat(),
                ),
            )
            db.execute(
                """UPDATE organisations SET status='deletion_pending', updated_at=?
                   WHERE tenant_id=?""",
                (now.isoformat(), tenant_id),
            )

    def cancel_tenant_deletion(self, tenant_id: str) -> bool:
        now = utc_now().isoformat()
        with self._connect() as db:
            changed = db.execute(
                """UPDATE tenant_deletion_requests SET status='cancelled',
                       cancelled_at=? WHERE tenant_id=? AND status='pending'""",
                (now, tenant_id),
            )
            if changed.rowcount == 1:
                db.execute(
                    """UPDATE organisations SET status='active', updated_at=?
                       WHERE tenant_id=? AND status='deletion_pending'""",
                    (now, tenant_id),
                )
        return changed.rowcount == 1

    def tenant_export_summary(self, tenant_id: str) -> dict[str, object]:
        with self._connect() as db:
            counts = {
                "memberships": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "agents": self._scalar(
                    db, "SELECT COUNT(*) FROM agents WHERE tenant_id=?", (tenant_id,)
                ),
                "agent_tokens": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM agent_tokens WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "approvals": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM approvals_v2 WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "actions": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM action_events WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "lineage_events": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM lineage_events WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "incidents": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM incidents WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "watch_tasks": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_tasks WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "watch_events": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_events WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "watch_findings": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM watch_findings WHERE tenant_id=?",
                    (tenant_id,),
                ),
                "intervention_plans": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM intervention_plans WHERE tenant_id=?",
                    (tenant_id,),
                ),
            }
        organisation = self.get_organisation(tenant_id)
        return {
            "tenant_id": tenant_id,
            "organisation": organisation.model_dump(mode="json")
            if organisation
            else None,
            "counts": counts,
            "generated_at": utc_now().isoformat(),
            "contains_secret_values": False,  # nosec B105
            "note": "Metadata inventory only; a full regulated-data export requires an approved runbook.",
        }

    @staticmethod
    def _membership(row: Any) -> TenantMembership:
        return TenantMembership(
            tenant_id=row["tenant_id"],
            subject=row["subject"],
            email=row["email"],
            role=MembershipRole(row["role"]),
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def store_watch_intelligence(
        self,
        result: WatchIntelligenceResult,
        agent_id: str,
        input_digest: str,
    ) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO watch_intelligence_analyses VALUES (
                       ?, ?, ?, ?, ?, ?, ?, ?, ?
                   )""",
                (
                    result.analysis_id,
                    result.tenant_id,
                    agent_id,
                    result.task_id,
                    result.model,
                    result.prompt_version,
                    input_digest,
                    json.dumps(result.model_dump(mode="json"), sort_keys=True),
                    result.created_at.isoformat(),
                ),
            )

    def upsert_response_policy(self, policy: ResponsePolicy) -> ResponsePolicy:
        with self._connect() as db:
            db.execute(
                """INSERT INTO response_policies VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, finding_code) DO UPDATE SET
                       action=excluded.action,
                       minimum_confidence=excluded.minimum_confidence,
                       deterministic_only=excluded.deterministic_only,
                       enabled=excluded.enabled,
                       updated_by=excluded.updated_by,
                       updated_at=excluded.updated_at""",
                (
                    policy.tenant_id,
                    policy.finding_code,
                    policy.action,
                    policy.minimum_confidence,
                    int(policy.deterministic_only),
                    int(policy.enabled),
                    policy.updated_by,
                    policy.updated_at.isoformat(),
                ),
            )
        return policy

    def response_policy(
        self, tenant_id: str, finding_code: str
    ) -> ResponsePolicy | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM response_policies WHERE tenant_id=? AND finding_code=?",
                (tenant_id, finding_code),
            ).fetchone()
        return self._response_policy_from_row(row) if row else None

    def list_response_policies(self, tenant_id: str) -> list[ResponsePolicy]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM response_policies WHERE tenant_id=? ORDER BY finding_code",
                (tenant_id,),
            ).fetchall()
        return [self._response_policy_from_row(row) for row in rows]

    def revoke_session_tokens(
        self, tenant_id: str, task_id: str, session_id: str, reason: str
    ) -> int:
        now = utc_now().isoformat()
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE agent_tokens SET revoked_at=?, revoke_reason=?
                   WHERE revoked_at IS NULL AND token_id IN (
                       SELECT token_id FROM watch_session_credentials
                       WHERE tenant_id=? AND task_id=? AND session_id=?
                   )""",
                (now, reason, tenant_id, task_id, session_id),
            )
        return cursor.rowcount

    @staticmethod
    def _response_policy_from_row(row: Any) -> ResponsePolicy:
        return ResponsePolicy(
            tenant_id=row["tenant_id"],
            finding_code=row["finding_code"],
            action=row["action"],
            minimum_confidence=row["minimum_confidence"],
            deterministic_only=bool(row["deterministic_only"]),
            enabled=bool(row["enabled"]),
            updated_by=row["updated_by"],
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _watch_task_from_row(row: Any) -> WatchTaskRecord:
        return WatchTaskRecord(
            task_id=row["task_id"],
            workflow_id=row["workflow_id"] or row["task_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            description=row["description"],
            profile=WatchProfile(row["profile"]),
            expected_tools=json.loads(row["expected_tools_json"]),
            success_criteria=json.loads(row["success_criteria_json"]),
            allow_multi_session=bool(row["allow_multi_session"]),
            max_runtime_seconds=row["max_runtime_seconds"],
            max_tool_calls=row["max_tool_calls"],
            max_cost_usd=row["max_cost_usd"],
            status=row["status"],
            event_count=row["event_count"],
            estimated_cost_usd=row["estimated_cost_usd"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
        )

    @staticmethod
    def _watch_finding_from_row(row: Any) -> WatchFinding:
        return WatchFinding(
            id=row["id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            task_id=row["task_id"],
            code=row["code"],
            severity=row["severity"],
            confidence=row["confidence"],
            summary=row["summary"],
            evidence=json.loads(row["evidence_json"]),
            recommended_action=row["recommended_action"],
            status=row["status"],
            occurrences=row["occurrences"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"])
                if row["resolved_at"]
                else None
            ),
            reviewer=row["reviewer"],
            note=row["note"],
            detector_type=row["detector_type"],
            analysis_id=row["analysis_id"],
        )

    @staticmethod
    def _intervention_from_row(row: Any) -> InterventionPlan:
        return InterventionPlan(
            id=row["id"],
            finding_id=row["finding_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            task_id=row["task_id"],
            action=InterventionAction(row["action"]),
            rationale=row["rationale"],
            parameters=json.loads(row["parameters_json"]),
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"])
                if row["resolved_at"]
                else None
            ),
            reviewer=row["reviewer"],
            note=row["note"],
        )

    def enqueue_outbox(
        self,
        kind: str,
        deduplication_key: str,
        payload: dict[str, Any],
        max_attempts: int = 8,
    ) -> str:
        job_id = str(uuid4())
        now = utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                """INSERT INTO outbox_jobs (
                       id, kind, deduplication_key, payload_json, status, attempts,
                       max_attempts, next_attempt_at, locked_by, locked_at, last_error,
                       created_at, completed_at
                   ) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, NULL, NULL, NULL, ?, NULL)
                   ON CONFLICT(kind, deduplication_key) DO NOTHING""",
                (
                    job_id,
                    kind,
                    deduplication_key,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    max_attempts,
                    now,
                    now,
                ),
            )
            row = db.execute(
                "SELECT id FROM outbox_jobs WHERE kind=? AND deduplication_key=?",
                (kind, deduplication_key),
            ).fetchone()
        return str(row["id"])

    def claim_outbox(
        self,
        worker_id: str,
        lease_seconds: int = 30,
    ) -> dict[str, Any] | None:
        now = utc_now()
        lease_expired = (now - timedelta(seconds=lease_seconds)).isoformat()
        with self._connect() as db:
            if self._postgres:
                row = db.execute(
                    """SELECT * FROM outbox_jobs
                       WHERE attempts < max_attempts AND next_attempt_at<=?
                       AND (status IN ('pending','retry')
                            OR (status='processing' AND locked_at<=?))
                       ORDER BY created_at, id
                       LIMIT 1 FOR UPDATE SKIP LOCKED""",
                    (now.isoformat(), lease_expired),
                ).fetchone()
            else:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    """SELECT * FROM outbox_jobs
                       WHERE attempts < max_attempts AND next_attempt_at<=?
                       AND (status IN ('pending','retry')
                            OR (status='processing' AND locked_at<=?))
                       ORDER BY created_at, id LIMIT 1""",
                    (now.isoformat(), lease_expired),
                ).fetchone()
            if not row:
                return None
            db.execute(
                """UPDATE outbox_jobs SET status='processing', attempts=attempts+1,
                   locked_by=?, locked_at=? WHERE id=?""",
                (worker_id, now.isoformat(), row["id"]),
            )
            claimed = db.execute(
                "SELECT * FROM outbox_jobs WHERE id=?", (row["id"],)
            ).fetchone()
        result = dict(claimed)
        result["payload"] = json.loads(result.pop("payload_json"))
        return result

    def complete_outbox(self, job_id: str, worker_id: str) -> bool:
        now = utc_now().isoformat()
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE outbox_jobs SET status='completed', completed_at=?,
                   locked_by=NULL, locked_at=NULL, last_error=NULL
                   WHERE id=? AND status='processing' AND locked_by=?""",
                (now, job_id, worker_id),
            )
            return cursor.rowcount == 1

    def retry_outbox(
        self,
        job_id: str,
        worker_id: str,
        error: str,
        delay_seconds: int,
    ) -> bool:
        next_attempt = (utc_now() + timedelta(seconds=delay_seconds)).isoformat()
        with self._connect() as db:
            row = db.execute(
                "SELECT attempts, max_attempts FROM outbox_jobs WHERE id=?",
                (job_id,),
            ).fetchone()
            if not row:
                return False
            status = "dead" if row["attempts"] >= row["max_attempts"] else "retry"
            cursor = db.execute(
                """UPDATE outbox_jobs SET status=?, next_attempt_at=?,
                   locked_by=NULL, locked_at=NULL, last_error=?
                   WHERE id=? AND status='processing' AND locked_by=?""",
                (status, next_attempt, error[:500], job_id, worker_id),
            )
            return cursor.rowcount == 1

    def list_outbox(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT id, kind, status, attempts, max_attempts, next_attempt_at,
                          locked_by, last_error, created_at, completed_at
                   FROM outbox_jobs ORDER BY created_at DESC, id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def heartbeat_worker(
        self,
        worker_id: str,
        *,
        processed_delta: int = 0,
        failed_delta: int = 0,
    ) -> None:
        now = utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                """INSERT INTO worker_heartbeats
                       (worker_id, started_at, last_seen, processed, failed)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(worker_id) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       processed=worker_heartbeats.processed + excluded.processed,
                       failed=worker_heartbeats.failed + excluded.failed""",
                (worker_id, now, now, processed_delta, failed_delta),
            )

    def worker_status(self, stale_after_seconds: int = 60) -> list[dict[str, Any]]:
        cutoff = (utc_now() - timedelta(seconds=stale_after_seconds)).isoformat()
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM worker_heartbeats ORDER BY last_seen DESC"
            ).fetchall()
        return [
            dict(row) | {"status": "online" if row["last_seen"] >= cutoff else "stale"}
            for row in rows
        ]

    def record_mcp_tool_observation(
        self,
        server_id: str,
        tool_name: str,
        digest: str,
        status: str,
        findings: list[str],
    ) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO mcp_tool_observations VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(server_id, tool_name) DO UPDATE SET
                   digest=excluded.digest, status=excluded.status,
                   findings_json=excluded.findings_json,
                   observed_at=excluded.observed_at""",
                (
                    server_id,
                    tool_name,
                    digest,
                    status,
                    json.dumps(sorted(set(findings))),
                    utc_now().isoformat(),
                ),
            )

    def get_mcp_tool_observation(
        self, server_id: str, tool_name: str
    ) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT * FROM mcp_tool_observations
                   WHERE server_id=? AND tool_name=?""",
                (server_id, tool_name),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["findings"] = json.loads(result.pop("findings_json"))
        return result

    def get_mcp_tool_baseline(
        self, server_id: str, tool_name: str
    ) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM mcp_tool_baselines WHERE server_id=? AND tool_name=?",
                (server_id, tool_name),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["definition"] = json.loads(result.pop("definition_json"))
        return result

    def mcp_tool_name_owners(self, tool_name: str, excluding: str) -> list[str]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT server_id FROM mcp_tool_baselines
                   WHERE tool_name=? AND server_id<>? ORDER BY server_id""",
                (tool_name, excluding),
            ).fetchall()
        return [str(row["server_id"]) for row in rows]

    def upsert_mcp_tool_baseline(
        self,
        server_id: str,
        tool_name: str,
        digest: str,
        definition: dict[str, Any],
        status: str,
    ) -> None:
        now = utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                """INSERT INTO mcp_tool_baselines VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(server_id, tool_name) DO UPDATE SET
                   digest=excluded.digest, definition_json=excluded.definition_json,
                   status=excluded.status, last_seen=excluded.last_seen""",
                (
                    server_id,
                    tool_name,
                    digest,
                    json.dumps(definition, sort_keys=True, separators=(",", ":")),
                    status,
                    now,
                    now,
                ),
            )

    def list_mcp_tool_baselines(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM mcp_tool_baselines ORDER BY server_id, tool_name"
            ).fetchall()
        return [
            {key: value for key, value in dict(row).items() if key != "definition_json"}
            | {"definition": json.loads(row["definition_json"])}
            for row in rows
        ]

    def record_policy_snapshot(self, snapshot: dict[str, Any]) -> None:
        protected = self._encrypt_blob(
            json.dumps(snapshot, separators=(",", ":"), default=str),
            b"sentinelgate-policy-snapshot-v1",
        )
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO policy_snapshots VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    snapshot["tenant_id"],
                    snapshot["agent_id"],
                    snapshot["call"]["trace_id"],
                    snapshot["call"]["tool_name"],
                    protected,
                    snapshot["created_at"],
                ),
            )
            db.execute(
                """DELETE FROM policy_snapshots WHERE id IN (
                       SELECT id FROM policy_snapshots ORDER BY created_at DESC LIMIT -1 OFFSET 5000
                   )"""
            )

    def list_policy_snapshots(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT protected_snapshot FROM policy_snapshots ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            json.loads(
                self._decrypt_blob(
                    row["protected_snapshot"], b"sentinelgate-policy-snapshot-v1"
                )
            )
            for row in rows
        ]

    def register_agent_token(
        self,
        principal: AgentPrincipal,
        owner: str,
    ) -> None:
        now = utc_now().isoformat()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO agents VALUES (?, ?, ?, 'active', ?, ?, ?)
                   ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
                   owner=excluded.owner, scopes_json=excluded.scopes_json,
                   status='active', updated_at=excluded.updated_at""",
                (
                    principal.tenant_id,
                    principal.agent_id,
                    owner,
                    json.dumps(sorted(principal.scopes)),
                    now,
                    now,
                ),
            )
            db.execute(
                "INSERT INTO agent_tokens VALUES (?, ?, ?, ?, NULL, NULL)",
                (
                    principal.token_id,
                    principal.tenant_id,
                    principal.agent_id,
                    principal.expires_at.isoformat(),
                ),
            )

    def token_is_active(self, principal: AgentPrincipal) -> bool:
        now = utc_now().isoformat()
        with self._connect() as db:
            row = db.execute(
                """SELECT t.revoked_at, t.expires_at, a.status
                   FROM agent_tokens t JOIN agents a
                     ON a.tenant_id=t.tenant_id AND a.agent_id=t.agent_id
                   WHERE t.token_id=? AND t.tenant_id=? AND t.agent_id=?""",
                (principal.token_id, principal.tenant_id, principal.agent_id),
            ).fetchone()
        return bool(
            row
            and row["revoked_at"] is None
            and row["expires_at"] > now
            and row["status"] == "active"
        )

    def revoke_agent_tokens(self, tenant_id: str, agent_id: str, reason: str) -> int:
        now = utc_now().isoformat()
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE agent_tokens SET revoked_at=?, revoke_reason=?
                   WHERE tenant_id=? AND agent_id=? AND revoked_at IS NULL""",
                (now, reason, tenant_id, agent_id),
            )
            db.execute(
                "UPDATE agents SET status='revoked', updated_at=? WHERE tenant_id=? AND agent_id=?",
                (now, tenant_id, agent_id),
            )
        return cursor.rowcount

    def list_agents(self, tenant_id: str | None = None) -> list[AgentRecord]:
        query = """SELECT a.*,
                   (SELECT COUNT(*) FROM agent_tokens t WHERE t.tenant_id=a.tenant_id
                    AND t.agent_id=a.agent_id AND t.revoked_at IS NULL
                    AND t.expires_at>?) AS active_tokens FROM agents a"""
        params: list[Any] = [utc_now().isoformat()]
        if tenant_id:
            query += " WHERE a.tenant_id=?"
            params.append(tenant_id)
        query += " ORDER BY a.updated_at DESC"
        with self._connect() as db:
            rows = db.execute(query, tuple(params)).fetchall()
        return [
            AgentRecord(
                tenant_id=row["tenant_id"],
                agent_id=row["agent_id"],
                owner=row["owner"],
                status=row["status"],
                scopes=json.loads(row["scopes_json"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                active_tokens=row["active_tokens"],
            )
            for row in rows
        ]

    def contain_agent(
        self,
        tenant_id: str,
        agent_id: str,
        mode: ContainmentMode,
        reason: str,
        reviewer: str,
        duration_seconds: int,
        allowed_tools: list[str],
        incident_id: str | None,
    ) -> ContainmentRecord:
        now = utc_now()
        record = ContainmentRecord(
            id=str(uuid4()),
            tenant_id=tenant_id,
            agent_id=agent_id,
            mode=mode,
            reason=reason,
            reviewer=reviewer,
            allowed_tools=sorted(set(allowed_tools)),
            incident_id=incident_id,
            created_at=now,
            expires_at=now + timedelta(seconds=duration_seconds),
        )
        with self._connect() as db:
            db.execute(
                "INSERT INTO containments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    record.id,
                    tenant_id,
                    agent_id,
                    mode.value,
                    reason,
                    reviewer,
                    json.dumps(record.allowed_tools),
                    incident_id,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat(),
                ),
            )
        if mode is ContainmentMode.REVOKE:
            self.revoke_agent_tokens(tenant_id, agent_id, reason)
        return record

    def active_containment(
        self, tenant_id: str, agent_id: str
    ) -> ContainmentRecord | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT * FROM containments WHERE tenant_id=? AND agent_id=?
                   AND released_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1""",
                (tenant_id, agent_id, utc_now().isoformat()),
            ).fetchone()
        return self._containment_from_row(row) if row else None

    def list_containments(self, active_only: bool = True) -> list[ContainmentRecord]:
        query = "SELECT * FROM containments"
        params: tuple[Any, ...] = ()
        if active_only:
            query += " WHERE released_at IS NULL AND expires_at>?"
            params = (utc_now().isoformat(),)
        query += " ORDER BY created_at DESC"
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return [self._containment_from_row(row) for row in rows]

    def release_containment(self, containment_id: str) -> bool:
        with self._connect() as db:
            cursor = db.execute(
                "UPDATE containments SET released_at=? WHERE id=? AND released_at IS NULL",
                (utc_now().isoformat(), containment_id),
            )
        return cursor.rowcount == 1

    def reserve_egress(
        self, tenant_id: str, agent_id: str, amount: int, hourly_limit: int
    ) -> bool:
        now = utc_now()
        cutoff = (now - timedelta(hours=1)).isoformat()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"egress:{tenant_id}:{agent_id}")
            db.execute("DELETE FROM egress_events WHERE created_at < ?", (cutoff,))
            used = db.execute(
                "SELECT COALESCE(SUM(bytes),0) AS total_bytes FROM egress_events WHERE tenant_id=? AND agent_id=? AND created_at>=?",
                (tenant_id, agent_id, cutoff),
            ).fetchone()["total_bytes"]
            if used + amount > hourly_limit:
                return False
            db.execute(
                "INSERT INTO egress_events VALUES (?, ?, ?, ?)",
                (tenant_id, agent_id, amount, now.isoformat()),
            )
        return True

    def egress_allowed(
        self, tenant_id: str, agent_id: str, amount: int, hourly_limit: int
    ) -> bool:
        cutoff = (utc_now() - timedelta(hours=1)).isoformat()
        with self._connect() as db:
            used = db.execute(
                """SELECT COALESCE(SUM(bytes),0) AS total_bytes FROM egress_events
                   WHERE tenant_id=? AND agent_id=? AND created_at>=?""",
                (tenant_id, agent_id, cutoff),
            ).fetchone()["total_bytes"]
        return bool(used + amount <= hourly_limit)

    def record_action(
        self,
        tenant_id: str,
        agent_id: str,
        trace_id: str,
        tool_name: str,
        category: str,
        decision: str,
    ) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO action_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant_id,
                    agent_id,
                    trace_id,
                    tool_name,
                    category,
                    decision,
                    utc_now().isoformat(),
                ),
            )

    def trace_has_category(
        self,
        tenant_id: str,
        agent_id: str,
        trace_id: str,
        category: str,
        window_seconds: int = 900,
    ) -> bool:
        cutoff = (utc_now() - timedelta(seconds=window_seconds)).isoformat()
        with self._connect() as db:
            row = db.execute(
                """SELECT 1 FROM action_events WHERE tenant_id=? AND agent_id=?
                   AND trace_id=? AND category=? AND created_at>=? LIMIT 1""",
                (tenant_id, agent_id, trace_id, category, cutoff),
            ).fetchone()
        return bool(row)

    def list_activity(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        trace_id: str | None = None,
    ) -> list[ActivityEvent]:
        filters: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("tenant_id", tenant_id),
            ("agent_id", agent_id),
            ("trace_id", trace_id),
        ):
            if value:
                filters.append(f"{column}=?")
                params.append(value)
        query = "SELECT * FROM action_events"
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(query, tuple(params)).fetchall()
        return [ActivityEvent(**dict(row)) for row in rows]

    def record_lineage(self, record: LineageRecord) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO lineage_events (
                   id, tenant_id, agent_id, trace_id, request_id, parent_ids_json,
                   source_type, source_id, destination, trust, classification,
                   labels_json, content_digest, created_at, field_taint_json
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT DO NOTHING""",
                (
                    record.id,
                    record.tenant_id,
                    record.agent_id,
                    record.trace_id,
                    record.request_id,
                    json.dumps(record.parent_ids),
                    record.source_type,
                    record.source_id,
                    record.destination,
                    record.trust.value,
                    record.classification.value,
                    json.dumps(sorted(set(record.labels))),
                    record.content_digest,
                    record.created_at.isoformat(),
                    json.dumps(
                        {
                            pointer: item.model_dump(mode="json")
                            for pointer, item in record.field_taint.items()
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )

    def list_lineage(
        self, trace_id: str, tenant_id: str | None = None
    ) -> list[LineageRecord]:
        query = "SELECT * FROM lineage_events WHERE trace_id=?"
        params: list[Any] = [trace_id]
        if tenant_id:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        query += " ORDER BY created_at, id"
        with self._connect() as db:
            rows = db.execute(query, tuple(params)).fetchall()
        return [self._lineage_from_row(row) for row in rows]

    def recent_agent_lineage(
        self,
        tenant_id: str,
        agent_id: str,
        window_seconds: int,
    ) -> list[LineageRecord]:
        cutoff = (utc_now() - timedelta(seconds=window_seconds)).isoformat()
        with self._connect() as db:
            rows = db.execute(
                """SELECT * FROM lineage_events WHERE tenant_id=? AND agent_id=?
                   AND created_at>=? ORDER BY created_at, id""",
                (tenant_id, agent_id, cutoff),
            ).fetchall()
        return [self._lineage_from_row(row) for row in rows]

    def trace_summary(
        self, tenant_id: str, agent_id: str, trace_id: str
    ) -> TraceSummary | None:
        records = self.list_lineage(trace_id, tenant_id)
        records = [item for item in records if item.agent_id == agent_id]
        return self._summarize_trace(records) if records else None

    def list_trace_summaries(self, limit: int = 100) -> list[TraceSummary]:
        with self._connect() as db:
            keys = db.execute(
                """SELECT tenant_id, agent_id, trace_id, MAX(created_at) AS last_seen
                   FROM lineage_events GROUP BY tenant_id, agent_id, trace_id
                   ORDER BY last_seen DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        summaries = []
        for key in keys:
            summary = self.trace_summary(
                key["tenant_id"], key["agent_id"], key["trace_id"]
            )
            if summary:
                summaries.append(summary)
        return summaries

    def append_audit(self, event_type: str, payload: dict[str, Any]) -> str:
        event_id = str(uuid4())
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        )
        with self._lock, self._connect() as db:
            self._transaction_lock(db, "audit-chain")
            row = db.execute(
                "SELECT event_hash, created_at FROM audit_events "
                "ORDER BY created_at DESC, id DESC LIMIT 1"
            ).fetchone()
            previous = row["event_hash"] if row else "GENESIS"
            created_at = utc_now()
            if row:
                prior_created_at = datetime.fromisoformat(row["created_at"])
                if created_at <= prior_created_at:
                    created_at = prior_created_at + timedelta(microseconds=1)
            created = created_at.isoformat()
            message = (
                f"{event_id}|{created}|{event_type}|{canonical}|{previous}".encode()
            )
            digest = hmac.new(self.key, message, hashlib.sha256).hexdigest()
            db.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, created, event_type, canonical, previous, digest),
            )
        return event_id

    def create_approval(
        self,
        request: ToolCallRequest,
        digest: str,
        principal: AgentPrincipal,
        ttl_seconds: int,
    ) -> ApprovalRecord:
        created = utc_now()
        record = ApprovalRecord(
            id=str(uuid4()),
            request=request,
            request_hash=digest,
            agent_id=principal.agent_id,
            tenant_id=principal.tenant_id,
            scopes=sorted(principal.scopes),
            status="pending",
            created_at=created,
            expires_at=created + timedelta(seconds=ttl_seconds),
        )
        with self._connect() as db:
            db.execute(
                "INSERT INTO approvals_v2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '')",
                (
                    record.id,
                    self._encrypt_request(request.model_dump_json()),
                    record.request_hash,
                    record.agent_id,
                    record.tenant_id,
                    json.dumps(record.scopes),
                    record.status,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat(),
                ),
            )
        return record

    def list_approvals(self, status: str | None = None) -> list[ApprovalRecord]:
        query = "SELECT * FROM approvals_v2"
        params: tuple[Any, ...] = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY created_at DESC"
        with self._connect() as db:
            rows = db.execute(query, params).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM approvals_v2 WHERE id=?", (approval_id,)
            ).fetchone()
        return self._approval_from_row(row) if row else None

    def resolve_approval(
        self, approval_id: str, status: str, reviewer: str, note: str
    ) -> ApprovalRecord | None:
        now = utc_now()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"approval:{approval_id}")
            row = db.execute(
                "SELECT * FROM approvals_v2 WHERE id=?", (approval_id,)
            ).fetchone()
            if (
                not row
                or row["status"] != "pending"
                or datetime.fromisoformat(row["expires_at"]) <= now
            ):
                return None
            db.execute(
                "UPDATE approvals_v2 SET status=?, resolved_at=?, reviewer=?, note=? WHERE id=?",
                (status, now.isoformat(), reviewer, note, approval_id),
            )
            row = db.execute(
                "SELECT * FROM approvals_v2 WHERE id=?", (approval_id,)
            ).fetchone()
        return self._approval_from_row(row)

    def consume_approval(self, approval_id: str) -> ApprovalRecord | None:
        now = utc_now()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"approval:{approval_id}")
            row = db.execute(
                "SELECT * FROM approvals_v2 WHERE id=?", (approval_id,)
            ).fetchone()
            if (
                not row
                or row["status"] != "approved"
                or datetime.fromisoformat(row["expires_at"]) <= now
            ):
                return None
            db.execute(
                "UPDATE approvals_v2 SET status='consumed' WHERE id=?", (approval_id,)
            )
            row = db.execute(
                "SELECT * FROM approvals_v2 WHERE id=?", (approval_id,)
            ).fetchone()
        return self._approval_from_row(row)

    def claim_execution(self, request_id: str, digest: str) -> bool:
        try:
            with self._connect() as db:
                db.execute(
                    "INSERT INTO executions VALUES (?, ?, 'running', ?, NULL)",
                    (request_id, digest, utc_now().isoformat()),
                )
            return True
        except DATABASE_INTEGRITY_ERRORS:
            return False

    def finish_execution(self, request_id: str, status: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE executions SET status=?, completed_at=? WHERE request_id=?",
                (status, utc_now().isoformat(), request_id),
            )

    def rate_allowed(
        self, tenant_id: str, agent_id: str, limit: int, window_seconds: int = 60
    ) -> bool:
        now = utc_now()
        cutoff = (now - timedelta(seconds=window_seconds)).isoformat()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"rate:{tenant_id}:{agent_id}")
            db.execute("DELETE FROM rate_events WHERE created_at < ?", (cutoff,))
            count = db.execute(
                "SELECT COUNT(*) AS n FROM rate_events WHERE tenant_id=? AND agent_id=? AND created_at>=?",
                (tenant_id, agent_id, cutoff),
            ).fetchone()["n"]
            if count >= limit:
                return False
            db.execute(
                "INSERT INTO rate_events VALUES (?, ?, ?)",
                (tenant_id, agent_id, now.isoformat()),
            )
        return True

    def account_rate_allowed(
        self,
        subject: str,
        action: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        """Atomically consume a rate-limit slot for an account-level action."""
        now = utc_now()
        cutoff = (now - timedelta(seconds=window_seconds)).isoformat()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"account-rate:{subject}:{action}")
            db.execute(
                "DELETE FROM account_rate_events WHERE created_at < ?", (cutoff,)
            )
            count = db.execute(
                "SELECT COUNT(*) AS n FROM account_rate_events "
                "WHERE subject=? AND action=? AND created_at>=?",
                (subject, action, cutoff),
            ).fetchone()["n"]
            if count >= limit:
                return False
            db.execute(
                "INSERT INTO account_rate_events VALUES (?, ?, ?)",
                (subject, action, now.isoformat()),
            )
        return True

    def record_violation(
        self,
        tenant_id: str,
        agent_id: str,
        severity: str,
        reason: str,
        window_seconds: int,
    ) -> int:
        now = utc_now()
        cutoff = (now - timedelta(seconds=window_seconds)).isoformat()
        with self._connect() as db:
            db.execute(
                "INSERT INTO violations VALUES (?, ?, ?, ?, ?)",
                (tenant_id, agent_id, severity, reason, now.isoformat()),
            )
            row = db.execute(
                """SELECT COUNT(*) AS n FROM violations
                   WHERE tenant_id=? AND agent_id=? AND created_at>=?
                   AND severity IN ('high','critical')""",
                (tenant_id, agent_id, cutoff),
            ).fetchone()
        return int(row["n"])

    def quarantine(self, tenant_id: str, agent_id: str, reason: str) -> None:
        with self._connect() as db:
            db.execute(
                """INSERT INTO quarantines VALUES (?, ?, ?, ?, NULL, NULL, '')
                   ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
                   reason=excluded.reason, created_at=excluded.created_at,
                   released_at=NULL, reviewer=NULL, note=''""",
                (tenant_id, agent_id, reason, utc_now().isoformat()),
            )
        self.contain_agent(
            tenant_id,
            agent_id,
            ContainmentMode.QUARANTINE,
            reason,
            "sentinelgate-auto-response",
            900,
            [],
            None,
        )

    def is_quarantined(self, tenant_id: str, agent_id: str) -> bool:
        active = self.active_containment(tenant_id, agent_id)
        if active and active.mode in {
            ContainmentMode.QUARANTINE,
            ContainmentMode.REVOKE,
        }:
            return True
        with self._connect() as db:
            row = db.execute(
                "SELECT 1 FROM quarantines WHERE tenant_id=? AND agent_id=? AND released_at IS NULL",
                (tenant_id, agent_id),
            ).fetchone()
        return bool(row)

    def release_agent(
        self, tenant_id: str, agent_id: str, reviewer: str, note: str
    ) -> bool:
        with self._connect() as db:
            cursor = db.execute(
                """UPDATE quarantines SET released_at=?, reviewer=?, note=?
                   WHERE tenant_id=? AND agent_id=? AND released_at IS NULL""",
                (utc_now().isoformat(), reviewer, note, tenant_id, agent_id),
            )
            db.execute(
                """UPDATE containments SET released_at=? WHERE tenant_id=? AND agent_id=?
                   AND released_at IS NULL AND mode='quarantine'""",
                (utc_now().isoformat(), tenant_id, agent_id),
            )
        return cursor.rowcount == 1

    def upsert_incident(
        self, tenant_id: str, agent_id: str, trace_id: str, severity: str, summary: str
    ) -> str:
        now = utc_now().isoformat()
        ranks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._transaction_lock(db, f"incident:{tenant_id}:{agent_id}:{trace_id}")
            row = db.execute(
                "SELECT * FROM incidents WHERE tenant_id=? AND agent_id=? AND trace_id=?",
                (tenant_id, agent_id, trace_id),
            ).fetchone()
            if row:
                chosen = (
                    severity
                    if ranks.get(severity, 1) > ranks.get(row["severity"], 1)
                    else row["severity"]
                )
                db.execute(
                    "UPDATE incidents SET severity=?, summary=?, event_count=event_count+1, last_seen=? WHERE id=?",
                    (chosen, summary, now, row["id"]),
                )
                return str(row["id"])
            incident_id = str(uuid4())
            db.execute(
                "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, 1, 'open', ?, ?)",
                (
                    incident_id,
                    tenant_id,
                    agent_id,
                    trace_id,
                    severity,
                    summary,
                    now,
                    now,
                ),
            )
        return incident_id

    def list_incidents(self, limit: int = 100) -> list[Incident]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Incident(**dict(row)) for row in rows]

    def update_incident(
        self, incident_id: str, status: str, reviewer: str, note: str
    ) -> Incident | None:
        with self._connect() as db:
            cursor = db.execute(
                "UPDATE incidents SET status=?, last_seen=? WHERE id=?",
                (status, utc_now().isoformat(), incident_id),
            )
            row = db.execute(
                "SELECT * FROM incidents WHERE id=?", (incident_id,)
            ).fetchone()
        if cursor.rowcount != 1 or not row:
            return None
        self.append_audit(
            "incident_status_changed",
            {
                "incident_id": incident_id,
                "status": status,
                "reviewer": reviewer,
                "note": note,
            },
        )
        return Incident(**dict(row))

    def metrics(self) -> dict[str, int]:
        with self._connect() as db:
            return {
                "audit_events": self._scalar(db, "SELECT COUNT(*) FROM audit_events"),
                "pending_approvals": self._scalar(
                    db, "SELECT COUNT(*) FROM approvals_v2 WHERE status='pending'"
                ),
                "open_incidents": self._scalar(
                    db, "SELECT COUNT(*) FROM incidents WHERE status='open'"
                ),
                "quarantined_agents": self._scalar(
                    db,
                    """SELECT COUNT(DISTINCT tenant_id || ':' || agent_id)
                       FROM containments WHERE released_at IS NULL AND expires_at>?
                       AND mode IN ('quarantine','revoke')""",
                    (utc_now().isoformat(),),
                ),
                "active_containments": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM containments WHERE released_at IS NULL AND expires_at>?",
                    (utc_now().isoformat(),),
                ),
                "registered_agents": self._scalar(db, "SELECT COUNT(*) FROM agents"),
                "successful_executions": self._scalar(
                    db, "SELECT COUNT(*) FROM executions WHERE status='succeeded'"
                ),
                "failed_executions": self._scalar(
                    db, "SELECT COUNT(*) FROM executions WHERE status='failed'"
                ),
                "tainted_traces": self._scalar(
                    db,
                    """SELECT COUNT(DISTINCT tenant_id || ':' || agent_id || ':' || trace_id)
                       FROM lineage_events WHERE classification IN ('confidential','restricted')
                       OR labels_json LIKE '%prompt_injection%'
                       OR labels_json LIKE '%customer-data%'
                       OR labels_json LIKE '%secret%'""",
                ),
                "mcp_tools_baselined": self._scalar(
                    db, "SELECT COUNT(*) FROM mcp_tool_baselines"
                ),
                "notification_jobs_pending": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM outbox_jobs WHERE status IN ('pending','retry','processing')",
                ),
                "notification_jobs_dead": self._scalar(
                    db, "SELECT COUNT(*) FROM outbox_jobs WHERE status='dead'"
                ),
                "watch_active_tasks": self._scalar(
                    db, "SELECT COUNT(*) FROM watch_tasks WHERE status='active'"
                ),
                "watch_open_findings": self._scalar(
                    db, "SELECT COUNT(*) FROM watch_findings WHERE status='open'"
                ),
                "watch_events": self._scalar(db, "SELECT COUNT(*) FROM watch_events"),
            }

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) | {"payload": json.loads(row["payload"])} for row in rows]

    def verify_audit_chain(self) -> bool:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY created_at, id"
            ).fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            message = f"{row['id']}|{row['created_at']}|{row['event_type']}|{row['payload']}|{previous}".encode()
            expected = hmac.new(self.key, message, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, row["event_hash"]):
                return False
            previous = row["event_hash"]
        return True

    def _encrypt_request(self, plaintext: str) -> str:
        return self._encrypt_blob(plaintext, b"sentinelgate-approval-v1")

    def _encrypt_blob(self, plaintext: str, purpose: bytes) -> str:
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, plaintext.encode("utf-8"), purpose)
        return "v1." + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt_request(self, protected: str) -> str:
        return self._decrypt_blob(protected, b"sentinelgate-approval-v1")

    def _decrypt_blob(self, protected: str, purpose: bytes) -> str:
        try:
            version, encoded = protected.split(".", 1)
            if version != "v1":
                raise StorageIntegrityError("Unsupported encrypted record version")
            payload = base64.urlsafe_b64decode(encoded)
            plaintext = self._cipher.decrypt(payload[:12], payload[12:], purpose)
            return plaintext.decode("utf-8")
        except (ValueError, InvalidTag, UnicodeDecodeError) as exc:
            raise StorageIntegrityError(
                "Encrypted record failed authentication"
            ) from exc

    def _approval_from_row(self, row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            id=row["id"],
            request=ToolCallRequest.model_validate_json(
                self._decrypt_request(row["request_json"])
            ),
            request_hash=row["request_hash"],
            agent_id=row["agent_id"],
            tenant_id=row["tenant_id"],
            scopes=json.loads(row["scopes_json"]),
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            resolved_at=datetime.fromisoformat(row["resolved_at"])
            if row["resolved_at"]
            else None,
            reviewer=row["reviewer"],
            note=row["note"],
        )

    @staticmethod
    def _containment_from_row(row: sqlite3.Row) -> ContainmentRecord:
        return ContainmentRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            mode=ContainmentMode(row["mode"]),
            reason=row["reason"],
            reviewer=row["reviewer"],
            allowed_tools=json.loads(row["allowed_tools_json"]),
            incident_id=row["incident_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            released_at=datetime.fromisoformat(row["released_at"])
            if row["released_at"]
            else None,
        )

    @staticmethod
    def _lineage_from_row(row: sqlite3.Row) -> LineageRecord:
        return LineageRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            trace_id=row["trace_id"],
            request_id=row["request_id"],
            parent_ids=json.loads(row["parent_ids_json"]),
            source_type=row["source_type"],
            source_id=row["source_id"],
            destination=row["destination"],
            trust=TrustLevel(row["trust"]),
            classification=DataClassification(row["classification"]),
            labels=json.loads(row["labels_json"]),
            content_digest=row["content_digest"],
            created_at=datetime.fromisoformat(row["created_at"]),
            field_taint=json.loads(row["field_taint_json"])
            if "field_taint_json" in row
            else {},
        )

    @staticmethod
    def _summarize_trace(records: list[LineageRecord]) -> TraceSummary:
        from sentinelgate.taint import highest_classification, least_trusted

        latest = max(item.created_at for item in records)
        return TraceSummary(
            tenant_id=records[0].tenant_id,
            agent_id=records[0].agent_id,
            trace_id=records[0].trace_id,
            trust=least_trusted(item.trust for item in records),
            classification=highest_classification(
                item.classification for item in records
            ),
            labels=sorted({label for item in records for label in item.labels}),
            node_count=len(records),
            last_seen=latest,
        )
