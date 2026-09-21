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
    LineageRecord,
    ToolCallRequest,
    TraceSummary,
    TrustLevel,
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
                raise RuntimeError("PostgreSQL support requires psycopg and psycopg-pool")
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
                """
            )
            if self._postgres:
                lineage_columns = {
                    row["column_name"]
                    for row in db.execute(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema='public' AND table_name='lineage_events'"
                    ).fetchall()
                }
            else:
                lineage_columns = {
                    row["name"]
                    for row in db.execute("PRAGMA table_info(lineage_events)")
                }
            if "field_taint_json" not in lineage_columns:
                db.execute(
                    "ALTER TABLE lineage_events ADD COLUMN field_taint_json "
                    "TEXT NOT NULL DEFAULT '{}'"
                )
            for version in ("0001_initial", "0002_field_taint"):
                db.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?) ON CONFLICT DO NOTHING",
                    (version, utc_now().isoformat()),
                )

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
                    server_id, tool_name, digest, status,
                    json.dumps(sorted(set(findings))), utc_now().isoformat(),
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
                tenant_id=row["tenant_id"], agent_id=row["agent_id"],
                owner=row["owner"], status=row["status"],
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
            id=str(uuid4()), tenant_id=tenant_id, agent_id=agent_id, mode=mode,
            reason=reason, reviewer=reviewer, allowed_tools=sorted(set(allowed_tools)),
            incident_id=incident_id, created_at=now,
            expires_at=now + timedelta(seconds=duration_seconds),
        )
        with self._connect() as db:
            db.execute(
                "INSERT INTO containments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    record.id, tenant_id, agent_id, mode.value, reason, reviewer,
                    json.dumps(record.allowed_tools), incident_id,
                    record.created_at.isoformat(), record.expires_at.isoformat(),
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
        self, tenant_id: str, agent_id: str, trace_id: str, tool_name: str,
        category: str, decision: str,
    ) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO action_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, agent_id, trace_id, tool_name, category, decision, utc_now().isoformat()),
            )

    def trace_has_category(
        self, tenant_id: str, agent_id: str, trace_id: str, category: str,
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
            ("tenant_id", tenant_id), ("agent_id", agent_id), ("trace_id", trace_id)
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
        created = utc_now().isoformat()
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        )
        with self._lock, self._connect() as db:
            self._transaction_lock(db, "audit-chain")
            row = db.execute(
                "SELECT event_hash FROM audit_events ORDER BY created_at DESC, id DESC LIMIT 1"
            ).fetchone()
            previous = row["event_hash"] if row else "GENESIS"
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
        if active and active.mode in {ContainmentMode.QUARANTINE, ContainmentMode.REVOKE}:
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
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if cursor.rowcount != 1 or not row:
            return None
        self.append_audit(
            "incident_status_changed",
            {"incident_id": incident_id, "status": status, "reviewer": reviewer, "note": note},
        )
        return Incident(**dict(row))

    def metrics(self) -> dict[str, int]:
        with self._connect() as db:
            return {
                "audit_events": self._scalar(db,
                    "SELECT COUNT(*) FROM audit_events"
                ),
                "pending_approvals": self._scalar(db,
                    "SELECT COUNT(*) FROM approvals_v2 WHERE status='pending'"
                ),
                "open_incidents": self._scalar(db,
                    "SELECT COUNT(*) FROM incidents WHERE status='open'"
                ),
                "quarantined_agents": self._scalar(db,
                    """SELECT COUNT(DISTINCT tenant_id || ':' || agent_id)
                       FROM containments WHERE released_at IS NULL AND expires_at>?
                       AND mode IN ('quarantine','revoke')""",
                    (utc_now().isoformat(),),
                ),
                "active_containments": self._scalar(db,
                    "SELECT COUNT(*) FROM containments WHERE released_at IS NULL AND expires_at>?",
                    (utc_now().isoformat(),),
                ),
                "registered_agents": self._scalar(db, "SELECT COUNT(*) FROM agents"),
                "successful_executions": self._scalar(db,
                    "SELECT COUNT(*) FROM executions WHERE status='succeeded'"
                ),
                "failed_executions": self._scalar(db,
                    "SELECT COUNT(*) FROM executions WHERE status='failed'"
                ),
                "tainted_traces": self._scalar(db,
                    """SELECT COUNT(DISTINCT tenant_id || ':' || agent_id || ':' || trace_id)
                       FROM lineage_events WHERE classification IN ('confidential','restricted')
                       OR labels_json LIKE '%prompt_injection%'
                       OR labels_json LIKE '%customer-data%'
                       OR labels_json LIKE '%secret%'"""
                ),
                "mcp_tools_baselined": self._scalar(db,
                    "SELECT COUNT(*) FROM mcp_tool_baselines"
                ),
            }

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
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
            id=row["id"], tenant_id=row["tenant_id"], agent_id=row["agent_id"],
            mode=ContainmentMode(row["mode"]), reason=row["reason"], reviewer=row["reviewer"],
            allowed_tools=json.loads(row["allowed_tools_json"]), incident_id=row["incident_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            released_at=datetime.fromisoformat(row["released_at"]) if row["released_at"] else None,
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
