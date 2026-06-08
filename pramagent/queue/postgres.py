"""
pramagent.queue.postgres
========================
Postgres-backed approval queue. The production choice — survives process
restarts, scales across workers, lets a webhook handler in one process
approve a request that another process is waiting on.

Uses ``psycopg`` (v3) if installed, falling back to ``psycopg2`` if not.
If neither is available, instantiation raises with a clear message instead
of silently importing a broken backend.
"""
from __future__ import annotations

import time
from typing import Optional

from .base import QueuedRequest, RequestStatus, from_row, to_row


_SCHEMA = """
CREATE TABLE IF NOT EXISTS pramagent_hitl_queue (
    request_id   TEXT PRIMARY KEY,
    action       TEXT NOT NULL,
    context      JSONB NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    created_at   DOUBLE PRECISION NOT NULL,
    decided_at   DOUBLE PRECISION,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pramagent_hitl_status
    ON pramagent_hitl_queue(status);
CREATE INDEX IF NOT EXISTS idx_pramagent_hitl_tenant
    ON pramagent_hitl_queue(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pramagent_hitl_created
    ON pramagent_hitl_queue(created_at);
"""


def _import_driver():
    try:
        import psycopg  # psycopg3
        return ("psycopg3", psycopg)
    except ImportError:
        psycopg = None
    try:
        import psycopg2  # psycopg2
        return ("psycopg2", psycopg2)
    except ImportError:
        psycopg2 = None
    return (None, None)


class PostgresHITLQueue:
    """Postgres-backed implementation of HITLQueueStore.

    Parameters
    ----------
    dsn : str
        Standard Postgres connection string (e.g. ``postgresql://user:pw@host/db``).
    table : str
        Override the table name; default ``pramagent_hitl_queue``.
    """

    def __init__(self, dsn: str, *, table: str = "pramagent_hitl_queue") -> None:
        flavor, driver = _import_driver()
        if driver is None:
            raise RuntimeError(
                "PostgresHITLQueue requires 'psycopg' (v3) or 'psycopg2'. "
                "Install with: pip install psycopg[binary]   (or)   pip install psycopg2-binary"
            )
        self._flavor = flavor
        self._driver = driver
        self.dsn = dsn
        self.table = table
        # validate table name strictly to keep parameterised queries safe
        if not table.replace("_", "").isalnum():
            raise ValueError(f"unsafe table name: {table!r}")
        with self._connect() as conn:
            with conn.cursor() as cur:
                schema = _SCHEMA.replace("pramagent_hitl_queue", table)
                cur.execute(schema)
            conn.commit()

    # ── driver-flavor helpers ──────────────────────────────────────────
    def _connect(self):
        if self._flavor == "psycopg3":
            return self._driver.connect(self.dsn)
        return self._driver.connect(self.dsn)

    @staticmethod
    def _rowdict(cur, row) -> dict:
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))

    # ── HITLQueueStore protocol ────────────────────────────────────────
    def enqueue(self, request: QueuedRequest) -> str:
        row = to_row(request)
        # Table name is strictly validated in __init__; all values are parameterized.
        sql = (
            f"INSERT INTO {self.table} "  # nosec B608
            "(request_id, action, context, tenant_id, created_at, "
            "decided_at, status, decided_by, notes) "
            "VALUES (%s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (request_id) DO NOTHING"
        )
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (
                    row["request_id"], row["action"], row["context"],
                    row["tenant_id"], row["created_at"], row["decided_at"],
                    row["status"], row["decided_by"], row["notes"],
                ))
            conn.commit()
        return request.request_id

    def get(self, request_id: str) -> Optional[QueuedRequest]:
        sql = f"SELECT * FROM {self.table} WHERE request_id = %s"  # nosec B608
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (request_id,))
                r = cur.fetchone()
                if not r:
                    return None
                d = self._rowdict(cur, r)
        # context arrives as a dict from psycopg3 JSONB; from_row handles both
        if isinstance(d.get("context"), dict):
            import json
            d["context"] = json.dumps(d["context"])
        return from_row(d)

    def list_pending(self, tenant_id: Optional[str] = None,
                     limit: int = 100) -> list[QueuedRequest]:
        if tenant_id:
            sql = (f"SELECT * FROM {self.table} "  # nosec B608
                   "WHERE status = %s AND tenant_id = %s "
                   "ORDER BY created_at ASC LIMIT %s")
            args = (RequestStatus.PENDING.value, tenant_id, int(limit))
        else:
            sql = (f"SELECT * FROM {self.table} "  # nosec B608
                   "WHERE status = %s ORDER BY created_at ASC LIMIT %s")
            args = (RequestStatus.PENDING.value, int(limit))
        out: list[QueuedRequest] = []
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, args)
                for r in cur.fetchall():
                    d = self._rowdict(cur, r)
                    if isinstance(d.get("context"), dict):
                        import json
                        d["context"] = json.dumps(d["context"])
                    out.append(from_row(d))
        return out

    def decide(self, request_id: str, *, approved: bool,
               decided_by: str = "", notes: str = "") -> bool:
        new_status = (RequestStatus.APPROVED.value if approved
                      else RequestStatus.DENIED.value)
        sql = (f"UPDATE {self.table} "  # nosec B608
               "SET status=%s, decided_at=%s, decided_by=%s, notes=%s "
               "WHERE request_id=%s AND status=%s")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (new_status, time.time(), decided_by, notes,
                                  request_id, RequestStatus.PENDING.value))
                changed = cur.rowcount > 0
            conn.commit()
        return changed

    def expire(self, request_id: str) -> bool:
        sql = (f"UPDATE {self.table} "  # nosec B608
               "SET status=%s, decided_at=%s "
               "WHERE request_id=%s AND status=%s")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (RequestStatus.EXPIRED.value, time.time(),
                                  request_id, RequestStatus.PENDING.value))
                changed = cur.rowcount > 0
            conn.commit()
        return changed
