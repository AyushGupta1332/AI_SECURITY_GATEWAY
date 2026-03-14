"""
Audit Database
==============
SQLite-backed audit storage for the AI Security Gateway.
Replaces the flat audit.log with a queryable, searchable database.

Features:
  - Structured audit event storage
  - Session tracking with TTL
  - Full-text search on decisions
  - Retention policies
  - Export to JSON/CSV
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Generator

DB_PATH = Path(__file__).parent.parent / "data" / "audit.db"


def _ensure_dir() -> None:
    """Ensure the data directory exists."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


class AuditDatabase:
    """
    Thread-safe SQLite audit database.
    Uses WAL mode for concurrent reads during writes.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = str(db_path or DB_PATH)
        _ensure_dir()
        self._local = threading.local()
        self._init_schema()

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        yield self._local.conn

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id          TEXT PRIMARY KEY,
                    timestamp   TEXT NOT NULL,
                    agent_id    TEXT NOT NULL,
                    tool        TEXT NOT NULL,
                    decision    TEXT NOT NULL,
                    risk_score  INTEGER NOT NULL,
                    flags       TEXT NOT NULL DEFAULT '[]',
                    reason      TEXT NOT NULL DEFAULT '',
                    parameters  TEXT DEFAULT '{}',
                    identity    TEXT DEFAULT '{}',
                    mode        TEXT DEFAULT 'default',
                    api_key     TEXT DEFAULT '',
                    ip_address  TEXT DEFAULT '',
                    duration_ms REAL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                    ON audit_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_agent
                    ON audit_events(agent_id);
                CREATE INDEX IF NOT EXISTS idx_audit_decision
                    ON audit_events(decision);
                CREATE INDEX IF NOT EXISTS idx_audit_tool
                    ON audit_events(tool);

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id  TEXT PRIMARY KEY,
                    user_id     TEXT NOT NULL,
                    agent_id    TEXT NOT NULL,
                    tenant      TEXT DEFAULT 'default',
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    request_count INTEGER DEFAULT 0,
                    metadata    TEXT DEFAULT '{}',
                    is_active   INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_active
                    ON sessions(is_active, expires_at);

                CREATE TABLE IF NOT EXISTS analytics_cache (
                    cache_key   TEXT PRIMARY KEY,
                    data        TEXT NOT NULL,
                    computed_at TEXT NOT NULL
                );
            """)
            conn.commit()

    # ── Audit Events ──────────────────────────────────────────

    def log_event(
        self,
        agent_id: str,
        tool: str,
        decision: str,
        risk_score: int,
        flags: list[str],
        reason: str,
        parameters: dict[str, Any] | None = None,
        identity: dict[str, Any] | None = None,
        mode: str = "default",
        api_key: str = "",
        ip_address: str = "",
        duration_ms: float = 0,
    ) -> str:
        """
        Log an audit event. Returns the event ID.
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO audit_events
                   (id, timestamp, agent_id, tool, decision, risk_score,
                    flags, reason, parameters, identity, mode,
                    api_key, ip_address, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id, timestamp, agent_id, tool, decision, risk_score,
                    json.dumps(flags), reason,
                    json.dumps(parameters or {}, default=str),
                    json.dumps(identity or {}, default=str),
                    mode, api_key, ip_address, duration_ms,
                ),
            )
            conn.commit()

        return event_id

    def query_events(
        self,
        agent_id: str | None = None,
        tool: str | None = None,
        decision: str | None = None,
        search: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """
        Query audit events with filtering, pagination.
        Returns { events: [...], total: int, limit: int, offset: int }.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if decision:
            conditions.append("decision LIKE ?")
            params.append(f"%{decision}%")
        if search:
            conditions.append("(reason LIKE ? OR flags LIKE ? OR agent_id LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        with self._get_conn() as conn:
            # Count total
            count_row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM audit_events {where}", params
            ).fetchone()
            total = count_row["cnt"] if count_row else 0

            # Fetch page
            rows = conn.execute(
                f"""SELECT * FROM audit_events {where}
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?""",
                params + [limit, offset],
            ).fetchall()

        events = []
        for row in rows:
            event = dict(row)
            event["flags"] = json.loads(event["flags"])
            event["parameters"] = json.loads(event["parameters"])
            event["identity"] = json.loads(event["identity"])
            events.append(event)

        return {
            "events": events,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        """Get a single audit event by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE id = ?", (event_id,)
            ).fetchone()

        if not row:
            return None

        event = dict(row)
        event["flags"] = json.loads(event["flags"])
        event["parameters"] = json.loads(event["parameters"])
        event["identity"] = json.loads(event["identity"])
        return event

    def get_stats(self) -> dict[str, Any]:
        """Get aggregate statistics for the dashboard."""
        with self._get_conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_events"
            ).fetchone()["cnt"]

            allowed = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_events WHERE decision LIKE '%ALLOWED%'"
            ).fetchone()["cnt"]

            denied = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_events WHERE decision LIKE '%DENIED%'"
            ).fetchone()["cnt"]

            avg_risk = conn.execute(
                "SELECT COALESCE(AVG(risk_score), 0) as avg FROM audit_events"
            ).fetchone()["avg"]

            # Last 24h counts
            since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            last_24h = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_events WHERE timestamp >= ?",
                (since_24h,),
            ).fetchone()["cnt"]

            # Top agents
            top_agents = conn.execute(
                """SELECT agent_id, COUNT(*) as cnt
                   FROM audit_events
                   GROUP BY agent_id
                   ORDER BY cnt DESC LIMIT 5"""
            ).fetchall()

            # Top denied reasons
            top_denials = conn.execute(
                """SELECT reason, COUNT(*) as cnt
                   FROM audit_events
                   WHERE decision LIKE '%DENIED%'
                   GROUP BY reason
                   ORDER BY cnt DESC LIMIT 5"""
            ).fetchall()

            # Injection attempts
            injections = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_events WHERE flags LIKE '%injection%'"
            ).fetchone()["cnt"]

        return {
            "total_events": total,
            "allowed": allowed,
            "denied": denied,
            "avg_risk_score": round(avg_risk, 1),
            "last_24h": last_24h,
            "injection_attempts": injections,
            "top_agents": [{"agent_id": r["agent_id"], "count": r["cnt"]} for r in top_agents],
            "top_denials": [{"reason": r["reason"][:100], "count": r["cnt"]} for r in top_denials],
        }

    def cleanup(self, retention_days: int = 90) -> int:
        """Delete events older than retention_days. Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM audit_events WHERE timestamp < ?", (cutoff,)
            )
            conn.commit()
            return cursor.rowcount

    def export_events(
        self,
        format: str = "json",
        limit: int = 1000,
        **filters: Any,
    ) -> str:
        """Export audit events as JSON or CSV string."""
        result = self.query_events(limit=limit, **filters)
        events = result["events"]

        if format == "csv":
            if not events:
                return "id,timestamp,agent_id,tool,decision,risk_score,flags,reason\n"
            lines = ["id,timestamp,agent_id,tool,decision,risk_score,flags,reason"]
            for e in events:
                flags_str = "; ".join(e["flags"]).replace(",", ";")
                reason_str = e["reason"].replace(",", ";").replace("\n", " ")
                lines.append(
                    f'{e["id"]},{e["timestamp"]},{e["agent_id"]},{e["tool"]},'
                    f'{e["decision"]},{e["risk_score"]},"{flags_str}","{reason_str}"'
                )
            return "\n".join(lines)

        return json.dumps(events, indent=2, default=str)

    # ── Session Management ────────────────────────────────────

    def create_session(
        self,
        user_id: str,
        agent_id: str,
        tenant: str = "default",
        ttl_minutes: int = 60,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new session. Returns session info."""
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=ttl_minutes)

        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO sessions
                   (session_id, user_id, agent_id, tenant, created_at,
                    expires_at, last_active, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id, user_id, agent_id, tenant,
                    now.isoformat(), expires.isoformat(), now.isoformat(),
                    json.dumps(metadata or {}),
                ),
            )
            conn.commit()

        return {
            "session_id": session_id,
            "user_id": user_id,
            "agent_id": agent_id,
            "tenant": tenant,
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }

    def validate_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Validate and refresh a session.
        Returns session data if valid, None if expired/not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._get_conn() as conn:
            row = conn.execute(
                """SELECT * FROM sessions
                   WHERE session_id = ? AND is_active = 1 AND expires_at > ?""",
                (session_id, now),
            ).fetchone()

            if not row:
                return None

            # Update last active and increment request count
            conn.execute(
                """UPDATE sessions
                   SET last_active = ?, request_count = request_count + 1
                   WHERE session_id = ?""",
                (now, session_id),
            )
            conn.commit()

        session = dict(row)
        session["metadata"] = json.loads(session["metadata"])
        return session

    def invalidate_session(self, session_id: str) -> bool:
        """Mark a session as inactive. Returns True if found."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE sessions SET is_active = 0 WHERE session_id = ?",
                (session_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_active_sessions(self, user_id: str | None = None) -> list[dict[str, Any]]:
        """List active sessions, optionally filtered by user."""
        now = datetime.now(timezone.utc).isoformat()
        query = "SELECT * FROM sessions WHERE is_active = 1 AND expires_at > ?"
        params: list[Any] = [now]

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        query += " ORDER BY last_active DESC"

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()

        sessions = []
        for row in rows:
            s = dict(row)
            s["metadata"] = json.loads(s["metadata"])
            sessions.append(s)
        return sessions

    def cleanup_sessions(self) -> int:
        """Deactivate expired sessions. Returns count cleaned."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE sessions SET is_active = 0 WHERE is_active = 1 AND expires_at < ?",
                (now,),
            )
            conn.commit()
            return cursor.rowcount


# ── Module-level singleton ────────────────────────────────────
_db: AuditDatabase | None = None


def get_audit_db() -> AuditDatabase:
    """Get or create the singleton audit database instance."""
    global _db
    if _db is None:
        _db = AuditDatabase()
    return _db
