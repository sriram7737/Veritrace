"""
pramagent.store
===============
Pluggable trace storage. MemoryStore is the zero-dependency default (traces
live in-process, lost on restart). SQLiteStore persists traces and the audit
hash chain to disk so they survive restarts — this is what a real deployment
uses.

Both stores implement the same protocol, so swapping is one line:

    from pramagent.store import SQLiteStore
    db = SQLiteStore("pramagent.db")
    armor = Pramagent(provider=..., store=db, audit=db)

SQLiteStore also implements the AuditBackend interface (append, verify_chain,
head, records), so a single object replaces both the in-memory store and the
in-memory hash chain — all persisted to one file.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Protocol, runtime_checkable

from .audit import canonical_hash, redact_chain_payload
from .types import TraceEvent


GENESIS = "0" * 64


# ──────────────────────────── protocol (duck-typing) ───────────────────────
@runtime_checkable
class TraceStore(Protocol):
    def save(self, trace: TraceEvent) -> None: ...
    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent: ...
    def list_all(self, limit: int | None = None) -> list[TraceEvent]: ...
    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int: ...
    def delete_for_tenant(self, tenant_id: str) -> int: ...


# ──────────────────────────── in-memory (default) ──────────────────────────
class MemoryStore:
    """Zero-dependency in-process store. Traces lost on restart."""

    def __init__(self) -> None:
        self._traces: list[TraceEvent] = []

    def save(self, trace: TraceEvent) -> None:
        self._traces.append(trace)

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        for t in self._traces:
            if t.call_id == call_id:
                if tenant_id is not None and t.tenant_id != tenant_id:
                    raise PermissionError(
                        f"trace {call_id} does not belong to tenant {tenant_id}")
                return t
        raise KeyError(call_id)

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        items = list(self._traces)
        if limit is not None:
            return items[-limit:]
        return items

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
        """Delete traces older than cutoff. Returns the count deleted. Use only
        after the EU AI Act minimum retention (six months) has elapsed.

        When tenant_id is given the prune is scoped to that tenant only, so one
        tenant can never prune another tenant's records."""
        before = len(self._traces)
        if tenant_id is None:
            self._traces = [t for t in self._traces if t.created_at >= cutoff_ts]
        else:
            self._traces = [
                t for t in self._traces
                if not (t.tenant_id == tenant_id and t.created_at < cutoff_ts)
            ]
        return before - len(self._traces)

    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure: delete all traces for a tenant. Returns the count deleted.
        MemoryStore does not hold the audit chain; when the audit backend is a
        separate object (the default HashChainBackend), call its
        redact_for_tenant() as well so chain payloads are tombstoned too —
        the API erase endpoint does both."""
        before = len(self._traces)
        self._traces = [t for t in self._traces if t.tenant_id != tenant_id]
        return before - len(self._traces)


# ──────────────────────────── SQLite (persistent) ──────────────────────────
class SQLiteStore:
    """
    Persists traces AND the audit hash chain to a single SQLite file. Implements
    both the TraceStore protocol and the AuditBackend protocol, so one object
    replaces both in-memory defaults.

    Tables:
        traces       — full TraceEvent as JSON + indexed columns for lookup
        audit_chain  — ordered chain records for tamper verification
    """

    def __init__(self, path: str = "pramagent.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
        self._create_tables()
        self._head = self._load_head()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS traces (
                call_id    TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                data       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_traces_tenant
                ON traces(tenant_id, session_id);
            CREATE INDEX IF NOT EXISTS idx_traces_time
                ON traces(created_at);

            CREATE TABLE IF NOT EXISTS audit_chain (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                payload    TEXT NOT NULL,
                prev_hash  TEXT NOT NULL,
                this_hash  TEXT NOT NULL
            );
        """)

    def close(self) -> None:
        self._conn.close()

    # ── TraceStore interface ──────────────────────────────────────────────
    def save(self, trace: TraceEvent) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO traces (call_id, tenant_id, session_id, created_at, data)"
            " VALUES (?, ?, ?, ?, ?)",
            (trace.call_id, trace.tenant_id, trace.session_id,
             trace.created_at, json.dumps(trace.to_dict(), sort_keys=True)),
        )
        self._conn.commit()

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        row = self._conn.execute(
            "SELECT data, tenant_id FROM traces WHERE call_id = ?", (call_id,)
        ).fetchone()
        if row is None:
            raise KeyError(call_id)
        if tenant_id is not None and row[1] != tenant_id:
            raise PermissionError(
                f"trace {call_id} does not belong to tenant {tenant_id}")
        return TraceEvent.from_dict(json.loads(row[0]))

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        sql = "SELECT data FROM traces ORDER BY created_at"
        if limit is not None:
            sql += f" DESC LIMIT {int(limit)}"
        rows = self._conn.execute(sql).fetchall()
        out = [TraceEvent.from_dict(json.loads(r[0])) for r in rows]
        if limit is not None:
            out.reverse()
        return out

    def list_by_tenant(self, tenant_id: str, session_id: str | None = None,
                       limit: int = 100) -> list[TraceEvent]:
        if session_id:
            rows = self._conn.execute(
                "SELECT data FROM traces WHERE tenant_id=? AND session_id=?"
                " ORDER BY created_at DESC LIMIT ?",
                (tenant_id, session_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM traces WHERE tenant_id=?"
                " ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [TraceEvent.from_dict(json.loads(r[0])) for r in rows]

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
        """Delete trace rows older than cutoff. Use only after the EU AI Act
        minimum retention (six months) has elapsed.

        When tenant_id is given the prune is scoped to that tenant only."""
        if tenant_id is None:
            cur = self._conn.execute(
                "DELETE FROM traces WHERE created_at < ?", (cutoff_ts,))
        else:
            cur = self._conn.execute(
                "DELETE FROM traces WHERE created_at < ? AND tenant_id = ?",
                (cutoff_ts, tenant_id))
        self._conn.commit()
        return cur.rowcount

    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure for one tenant: deletes the trace rows AND redacts the
        tenant's payloads inside audit_chain. Chain links are never deleted
        (that would orphan every subsequent hash); instead the PII-bearing
        fields are tombstoned and the chain is re-anchored — every link from
        the first redaction onward is re-hashed so verification still
        succeeds without the erased content."""
        cur = self._conn.execute(
            "DELETE FROM traces WHERE tenant_id = ?", (tenant_id,))
        self.redact_for_tenant(tenant_id)
        self._conn.commit()
        return cur.rowcount

    def redact_for_tenant(self, tenant_id: str) -> int:
        """Tombstone PII fields in this tenant's chain payloads (see
        pramagent.audit.redact_chain_payload), then re-anchor the chain:
        every link from the first redaction onward gets recomputed prev/this
        hashes so verify_chain() still passes. Returns payloads redacted."""
        rows = self._conn.execute(
            "SELECT seq, payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        prev = GENESIS
        redacted = 0
        rehash = False
        for seq, payload_json, _stored_prev, stored_hash in rows:
            payload = json.loads(payload_json)
            if payload.get("tenant_id") == tenant_id and redact_chain_payload(payload):
                redacted += 1
                rehash = True
            if rehash:
                new_hash = canonical_hash(payload, prev)
                self._conn.execute(
                    "UPDATE audit_chain SET payload = ?, prev_hash = ?, this_hash = ?"
                    " WHERE seq = ?",
                    (json.dumps(payload, sort_keys=True, separators=(",", ":")),
                     prev, new_hash, seq))
                prev = new_hash
            else:
                prev = stored_hash
        if rehash:
            self._head = prev
            self._conn.commit()
        return redacted

    # ── AuditBackend interface ────────────────────────────────────────────
    @property
    def head(self) -> str:
        return self._head

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        prev = prev_hash if prev_hash is not None else self._head
        this_hash = canonical_hash(payload, prev)
        self._conn.execute(
            "INSERT INTO audit_chain (payload, prev_hash, this_hash) VALUES (?, ?, ?)",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),
             prev, this_hash),
        )
        self._conn.commit()
        self._head = this_hash
        return this_hash, f"sqlite:{this_hash[:16]}"

    def verify_chain(self) -> bool:
        rows = self._conn.execute(
            "SELECT payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        prev = GENESIS
        for payload_json, stored_prev, stored_hash in rows:
            payload = json.loads(payload_json)
            expected = canonical_hash(payload, prev)
            if expected != stored_hash or stored_prev != prev:
                return False
            prev = stored_hash
        return True

    def records(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        return [
            {"payload": json.loads(r[0]), "prev_hash": r[1], "this_hash": r[2]}
            for r in rows
        ]

    def _load_head(self) -> str:
        row = self._conn.execute(
            "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS
