"""
pramagent.store_encrypted
=========================
EncryptedSQLiteStore — application-level encryption of sensitive payloads at
rest. Same interface as SQLiteStore; drop-in replacement.

Design choice
-------------
Two practical paths exist for SQLite-at-rest encryption:

  (a) Full-database encryption (SQLCipher / sqleet). Requires a custom system
      build of SQLite. Strong, but adds a system dependency that complicates
      installs.

  (b) Application-level field encryption. Encrypt the payload columns the app
      writes (trace JSON, audit-payload JSON) using a symmetric AEAD primitive,
      and leave indexed columns (call_id, tenant_id, created_at) in plain text
      so the database can still query them. Plain-Python; no system deps.

This module implements (b) using Fernet (AES-128-CBC + HMAC-SHA256 via the
`cryptography` package). It is the right default for the prototype: real PII
and trace content are encrypted at rest, while operational queries still work.

Key management
--------------
The encryption key is supplied to the constructor or read from the
PRAMAGENT_ENCRYPTION_KEY environment variable. Generate one with::

    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())

The key MUST be stored in a secret manager (AWS Secrets Manager, Vault, etc.)
in production. The store does not log the key, derive it from passwords, or
attempt key rotation — those concerns belong upstream and a real deployment
should layer them on (envelope encryption with a KMS data key is the usual
production pattern).
"""
from __future__ import annotations

import json
import os
import sqlite3

from .audit import canonical_hash
from .store import GENESIS
from .types import TraceEvent


class EncryptedSQLiteStore:
    """SQLite store with application-level encryption on payload columns.

    Indexed columns (call_id, tenant_id, session_id, created_at, prev_hash,
    this_hash) remain in plain text so the database can index and query them.
    All free-form content (trace JSON, audit-payload JSON) is encrypted with
    Fernet before INSERT and decrypted on SELECT.

    The hash chain is computed over the *plaintext* payload, exactly as in
    SQLiteStore, so verify_chain() works identically — the encryption layer is
    invisible to the audit semantics.
    """

    def __init__(self, path: str = "pramagent.db", key: bytes | str | None = None) -> None:
        try:
            from cryptography.fernet import Fernet
        except ImportError as e:
            raise RuntimeError(
                "EncryptedSQLiteStore requires the 'cryptography' package. "
                "Install with: pip install 'pramagent[encrypted]'"
            ) from e

        if key is None:
            key = os.environ.get("PRAMAGENT_ENCRYPTION_KEY")
        if not key:
            raise ValueError(
                "encryption key required: pass key= or set PRAMAGENT_ENCRYPTION_KEY"
            )
        self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())

        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._head = self._load_head()

    # ── encryption helpers ────────────────────────────────────────────────
    def _encrypt(self, data: str) -> bytes:
        return self._fernet.encrypt(data.encode("utf-8"))

    def _decrypt(self, blob: bytes) -> str:
        return self._fernet.decrypt(blob).decode("utf-8")

    # ── schema ────────────────────────────────────────────────────────────
    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS traces (
                call_id    TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                data_enc   BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_traces_tenant
                ON traces(tenant_id, session_id);
            CREATE INDEX IF NOT EXISTS idx_traces_time
                ON traces(created_at);

            CREATE TABLE IF NOT EXISTS audit_chain (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_enc BLOB NOT NULL,
                prev_hash   TEXT NOT NULL,
                this_hash   TEXT NOT NULL
            );
        """)

    def close(self) -> None:
        self._conn.close()

    # ── TraceStore interface ──────────────────────────────────────────────
    def save(self, trace: TraceEvent) -> None:
        blob = self._encrypt(json.dumps(trace.to_dict(), sort_keys=True))
        self._conn.execute(
            "INSERT OR REPLACE INTO traces "
            " (call_id, tenant_id, session_id, created_at, data_enc)"
            " VALUES (?, ?, ?, ?, ?)",
            (trace.call_id, trace.tenant_id, trace.session_id,
             trace.created_at, blob),
        )
        self._conn.commit()

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        row = self._conn.execute(
            "SELECT data_enc, tenant_id FROM traces WHERE call_id = ?", (call_id,)
        ).fetchone()
        if row is None:
            raise KeyError(call_id)
        if tenant_id is not None and row[1] != tenant_id:
            raise PermissionError(
                f"trace {call_id} does not belong to tenant {tenant_id}")
        return TraceEvent.from_dict(json.loads(self._decrypt(row[0])))

    def list_all(self) -> list[TraceEvent]:
        rows = self._conn.execute(
            "SELECT data_enc FROM traces ORDER BY created_at"
        ).fetchall()
        return [TraceEvent.from_dict(json.loads(self._decrypt(r[0]))) for r in rows]

    def list_by_tenant(self, tenant_id: str, session_id: str | None = None,
                       limit: int = 100) -> list[TraceEvent]:
        if session_id:
            rows = self._conn.execute(
                "SELECT data_enc FROM traces WHERE tenant_id=? AND session_id=?"
                " ORDER BY created_at DESC LIMIT ?",
                (tenant_id, session_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data_enc FROM traces WHERE tenant_id=?"
                " ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [TraceEvent.from_dict(json.loads(self._decrypt(r[0]))) for r in rows]

    def prune_older_than(self, cutoff_ts: float) -> int:
        cur = self._conn.execute(
            "DELETE FROM traces WHERE created_at < ?", (cutoff_ts,))
        self._conn.commit()
        return cur.rowcount

    def delete_for_tenant(self, tenant_id: str) -> int:
        cur = self._conn.execute(
            "DELETE FROM traces WHERE tenant_id = ?", (tenant_id,))
        self._conn.commit()
        return cur.rowcount

    # ── AuditBackend interface ────────────────────────────────────────────
    @property
    def head(self) -> str:
        return self._head

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        prev = prev_hash if prev_hash is not None else self._head
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        this_hash = canonical_hash(payload, prev)
        self._conn.execute(
            "INSERT INTO audit_chain (payload_enc, prev_hash, this_hash) VALUES (?, ?, ?)",
            (self._encrypt(canonical_json), prev, this_hash),
        )
        self._conn.commit()
        self._head = this_hash
        return this_hash, f"sqlite-enc:{this_hash[:16]}"

    def verify_chain(self) -> bool:
        rows = self._conn.execute(
            "SELECT payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        prev = GENESIS
        for payload_enc, stored_prev, stored_hash in rows:
            try:
                payload = json.loads(self._decrypt(payload_enc))
            except Exception:
                return False    # tampering with ciphertext or wrong key
            expected = canonical_hash(payload, prev)
            if expected != stored_hash or stored_prev != prev:
                return False
            prev = stored_hash
        return True

    def records(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        return [
            {"payload": json.loads(self._decrypt(r[0])),
             "prev_hash": r[1], "this_hash": r[2]}
            for r in rows
        ]

    def _load_head(self) -> str:
        row = self._conn.execute(
            "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS
