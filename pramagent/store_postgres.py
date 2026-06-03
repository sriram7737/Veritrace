"""
pramagent.store_postgres
========================
PostgreSQL implementations of the Store and HashChainBackend interfaces.

Operational features
--------------------
- Connection pooling via a thread-local connection cache with max_pool_size cap
  (True pooling would use psycopg2.pool.ThreadedConnectionPool or pgbouncer; this
  is a lightweight production-oriented approach without adding another dependency)
- Exponential-backoff retry on transient errors (OperationalError, InterfaceError)
- Circuit breaker: opens after threshold consecutive failures, auto-resets after
  cooldown_s; prevents cascade when Postgres is flapping
- Startup validation: connects and runs a test query on construction; raises
  PostgresUnavailable early so misconfiguration is caught at boot, not at runtime
- Auto-DDL: creates tables if they don't exist (idempotent)
- Graceful degradation: callers can catch PostgresUnavailable and fall back to
  MemoryStore / HashChainBackend so the system stays partially operational

Usage
-----
    from pramagent.store_postgres import PostgresStore
    db = PostgresStore.from_dsn(
        "postgresql://user:pass@host:5432/pramagent",
        max_pool_size=10,
        max_retries=3,
    )
    armor = Pramagent(store=db, audit=db)
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from dataclasses import asdict
from typing import Any, List, Optional

log = logging.getLogger(__name__)


class PostgresUnavailable(RuntimeError):
    """Raised when Postgres is configured but unreachable or misconfigured."""


class PostgresCircuitOpen(RuntimeError):
    """Raised when the Postgres circuit breaker has tripped."""


# ─────────────────────────── retry helper ─────────────────────────────────

def _retry(fn, *, max_attempts: int = 3, base_delay_s: float = 0.1,
           max_delay_s: float = 2.0):
    """Run fn() with exponential backoff + full jitter. Re-raises on last attempt."""
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as exc:
            _is_transient = _transient(exc)
            if attempt == max_attempts - 1 or not _is_transient:
                raise
            delay = min(base_delay_s * (2 ** attempt) + random.uniform(0, 0.05), max_delay_s)
            log.warning("postgres retry %d/%d in %.2fs: %s", attempt + 1, max_attempts, delay, exc)
            time.sleep(delay)


def _transient(exc: Exception) -> bool:
    """True for errors that are worth retrying (connection blips, timeouts)."""
    try:
        import psycopg2
        return isinstance(exc, (psycopg2.OperationalError, psycopg2.InterfaceError))
    except ImportError:
        return False


# ─────────────────────────── circuit breaker ──────────────────────────────

class _CircuitBreaker:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, threshold: int = 5, cooldown_s: float = 30.0) -> None:
        self._threshold = threshold
        self._cooldown_s = cooldown_s
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._state = self.CLOSED
        self._lock = threading.Lock()

    def _effective_state(self) -> str:
        if self._state == self.OPEN:
            if time.monotonic() - (self._opened_at or 0) >= self._cooldown_s:
                return self.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        with self._lock:
            return self._effective_state() != self.OPEN

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                log.error("Postgres circuit breaker OPENED after %d failures", self._failures)

    @property
    def state(self) -> str:
        with self._lock:
            return self._effective_state()


# ─────────────────────── connection pool (thread-local) ───────────────────

class _ThreadLocalPool:
    """Thread-local psycopg2 connections with a global cap on open connections.

    Each thread gets at most one connection. The global cap prevents runaway
    thread-proliferation from exhausting Postgres max_connections.
    """

    def __init__(self, dsn: str, max_pool_size: int = 10) -> None:
        self._dsn = dsn
        self._max_pool_size = max_pool_size
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self._open_count = 0

    def get(self):
        """Return a healthy connection for the current thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                # lightweight liveness check — no round-trip
                if conn.closed == 0:
                    return conn
            except Exception:
                pass
            # stale connection: evict and reopen
            with self._count_lock:
                self._open_count -= 1
            self._local.conn = None

        with self._count_lock:
            if self._open_count >= self._max_pool_size:
                raise PostgresUnavailable(
                    f"Postgres pool exhausted ({self._max_pool_size} connections open)"
                )
            self._open_count += 1

        try:
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(self._dsn)
            conn.autocommit = False
        except Exception as exc:
            with self._count_lock:
                self._open_count -= 1
            raise PostgresUnavailable(f"Could not connect to Postgres: {exc}") from exc

        self._local.conn = conn
        return conn

    def close_current(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None
            with self._count_lock:
                self._open_count -= 1

    @property
    def open_count(self) -> int:
        with self._count_lock:
            return self._open_count


# ─────────────────────────── base class ───────────────────────────────────

class _PostgresBase:
    """Shared pool + circuit-breaker + retry infrastructure."""

    _DDL_TRACES = """
    CREATE TABLE IF NOT EXISTS pramagent_traces (
        id          BIGSERIAL PRIMARY KEY,
        tenant_id   TEXT NOT NULL,
        session_id  TEXT NOT NULL,
        trace_id    TEXT NOT NULL UNIQUE,
        payload     JSONB NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS pramagent_traces_tenant ON pramagent_traces(tenant_id);
    CREATE INDEX IF NOT EXISTS pramagent_traces_created ON pramagent_traces(created_at);
    """

    _DDL_CHAIN = """
    CREATE TABLE IF NOT EXISTS pramagent_chain (
        id          BIGSERIAL PRIMARY KEY,
        this_hash   TEXT NOT NULL UNIQUE,
        prev_hash   TEXT NOT NULL,
        payload     JSONB NOT NULL,
        anchor_tx   TEXT NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """

    def __init__(
        self,
        dsn: str,
        *,
        max_pool_size: int = 10,
        max_retries: int = 3,
        base_delay_s: float = 0.1,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
    ) -> None:
        self._pool = _ThreadLocalPool(dsn, max_pool_size=max_pool_size)
        self._max_retries = max_retries
        self._base_delay_s = base_delay_s
        self._breaker = _CircuitBreaker(threshold=breaker_threshold, cooldown_s=breaker_cooldown_s)
        self._head_lock = threading.Lock()
        self._head = "0" * 64

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        max_pool_size: int = 10,
        max_retries: int = 3,
        base_delay_s: float = 0.1,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
    ) -> "_PostgresBase":
        """Construct, validate connectivity, run DDL, return instance."""
        instance = cls(
            dsn,
            max_pool_size=max_pool_size,
            max_retries=max_retries,
            base_delay_s=base_delay_s,
            breaker_threshold=breaker_threshold,
            breaker_cooldown_s=breaker_cooldown_s,
        )
        instance._validate_and_init()
        return instance

    def _validate_and_init(self) -> None:
        """Ping Postgres and create tables. Raises PostgresUnavailable on failure."""
        try:
            self._execute_ddl()
        except PostgresUnavailable:
            raise
        except Exception as exc:
            raise PostgresUnavailable(f"Postgres startup validation failed: {exc}") from exc

    def _execute_ddl(self) -> None:
        conn = self._pool.get()
        with conn.cursor() as cur:
            cur.execute(self._DDL_TRACES)
            cur.execute(self._DDL_CHAIN)
            # load head hash from chain on startup
            cur.execute("SELECT this_hash FROM pramagent_chain ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                self._head = row[0]
        conn.commit()
        log.info("PostgresStore DDL complete, chain head=%s", self._head[:12])

    def _run(self, fn):
        """Execute fn(conn, cursor) with circuit-breaker + retry."""
        if not self._breaker.allow():
            raise PostgresCircuitOpen("Postgres circuit breaker is open")
        def _attempt():
            conn = self._pool.get()
            try:
                with conn.cursor() as cur:
                    result = fn(conn, cur)
                conn.commit()
                return result
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    self._pool.close_current()
                raise
        try:
            result = _retry(_attempt, max_attempts=self._max_retries,
                            base_delay_s=self._base_delay_s)
            self._breaker.record_success()
            return result
        except (PostgresUnavailable, PostgresCircuitOpen):
            raise
        except Exception:
            self._breaker.record_failure()
            raise

    @property
    def circuit_state(self) -> str:
        return self._breaker.state

    @property
    def pool_open_count(self) -> int:
        return self._pool.open_count


# ──────────────────────────── Store impl ──────────────────────────────────

class PostgresStore(_PostgresBase):
    """PostgreSQL-backed Store + HashChainBackend.

    Implements both interfaces so a single instance can be passed as both
    ``store=db`` and ``audit=db`` to Pramagent.
    """

    # ── Store interface ───────────────────────────────────────────────────

    def save(self, trace) -> None:
        payload = trace.to_dict() if hasattr(trace, "to_dict") else vars(trace)
        trace_id = payload.get("this_hash") or payload.get("input_hash", "")

        def _fn(conn, cur):
            cur.execute(
                """
                INSERT INTO pramagent_traces (tenant_id, session_id, trace_id, payload)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (trace_id) DO UPDATE SET payload = EXCLUDED.payload
                """,
                (
                    payload.get("tenant_id", ""),
                    payload.get("session_id", ""),
                    trace_id,
                    json.dumps(payload),
                ),
            )
        self._run(_fn)

    def get(self, trace_id: str) -> Optional[dict]:
        def _fn(conn, cur):
            cur.execute("SELECT payload FROM pramagent_traces WHERE trace_id = %s", (trace_id,))
            row = cur.fetchone()
            return json.loads(row[0]) if row else None
        return self._run(_fn)

    def list_for_tenant(self, tenant_id: str, limit: int = 100) -> List[dict]:
        def _fn(conn, cur):
            cur.execute(
                "SELECT payload FROM pramagent_traces WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, limit),
            )
            return [json.loads(r[0]) for r in cur.fetchall()]
        return self._run(_fn)

    def delete_for_tenant(self, tenant_id: str) -> int:
        def _fn(conn, cur):
            cur.execute("DELETE FROM pramagent_traces WHERE tenant_id = %s", (tenant_id,))
            return cur.rowcount
        return self._run(_fn)

    def prune_older_than(self, cutoff_ts: float) -> int:
        """Delete traces older than UNIX timestamp cutoff_ts. Returns count deleted."""
        import datetime
        dt = datetime.datetime.utcfromtimestamp(cutoff_ts).replace(
            tzinfo=datetime.timezone.utc
        )
        def _fn(conn, cur):
            cur.execute("DELETE FROM pramagent_traces WHERE created_at < %s", (dt,))
            return cur.rowcount
        return self._run(_fn)

    # ── HashChainBackend interface ────────────────────────────────────────

    @property
    def head(self) -> str:
        with self._head_lock:
            return self._head

    def append(self, payload: dict, prev_hash: str) -> tuple[str, str]:
        import hashlib
        blob = json.dumps(payload, sort_keys=True).encode()
        this_hash = hashlib.sha256(blob).hexdigest()

        def _fn(conn, cur):
            cur.execute(
                """
                INSERT INTO pramagent_chain (this_hash, prev_hash, payload)
                VALUES (%s, %s, %s)
                ON CONFLICT (this_hash) DO NOTHING
                """,
                (this_hash, prev_hash, json.dumps(payload)),
            )
        self._run(_fn)

        with self._head_lock:
            self._head = this_hash
        return this_hash, ""  # anchor_tx_id placeholder

    def verify(self) -> list[dict]:
        """Verify hash-chain integrity. Returns list of broken links (empty = ok)."""
        def _fn(conn, cur):
            cur.execute(
                "SELECT this_hash, prev_hash, payload FROM pramagent_chain ORDER BY id ASC"
            )
            return cur.fetchall()
        rows = self._run(_fn)

        import hashlib
        broken = []
        for this_hash, prev_hash, payload_str in rows:
            payload = json.loads(payload_str)
            blob = json.dumps(payload, sort_keys=True).encode()
            expected = hashlib.sha256(blob).hexdigest()
            if expected != this_hash:
                broken.append({"this_hash": this_hash, "reason": "hash mismatch"})
        return broken

    # ── compliance export ─────────────────────────────────────────────────

    def export_audit_jsonl(self, tenant_id: str, out_path: str) -> int:
        """Export all audit chain entries for a tenant as JSONL. Returns count."""
        rows = self.list_for_tenant(tenant_id, limit=100_000)
        with open(out_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        return len(rows)
