"""Tests for PostgresStore (audit Finding #7): hash chain, tenant isolation,
and GDPR erasure on the Postgres backend.

Uses an in-memory fake driver implementing the exact SQL surface
PostgresStore issues (the same pattern as test_auth.py's fake Postgres
registry). The fake returns JSONB columns as dicts, matching the real
psycopg/psycopg2 behaviour, so the str/dict payload handling is exercised
the way production would exercise it. Swap `connect=` for a real DSN or a
testcontainers fixture to run the identical assertions against live Postgres.
"""
import json
import re

import pytest

from pramagent.store_postgres import PostgresStore, PostgresUnavailable
from pramagent.types import TraceEvent


# ─────────────────────────── fake psycopg driver ──────────────────────────

class _FakeDB:
    def __init__(self):
        self.traces: dict[str, dict] = {}     # trace_id -> row
        self.chain: list[dict] = []           # ordered rows
        self._chain_seq = 0

    def next_chain_id(self) -> int:
        self._chain_seq += 1
        return self._chain_seq


class _FakeCursor:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.rowcount = 0
        self._rows: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        sql_norm = " ".join(sql.lower().split())
        params = params or ()
        if "create table" in sql_norm or "create index" in sql_norm:
            return
        if "insert into pramagent_traces" in sql_norm:
            tenant_id, session_id, trace_id, payload = params
            self.db.traces[trace_id] = {
                "tenant_id": tenant_id, "session_id": session_id,
                "trace_id": trace_id, "payload": json.loads(payload),
            }
            self.rowcount = 1
            return
        if "select payload from pramagent_traces where trace_id" in sql_norm:
            row = self.db.traces.get(params[0])
            self._rows = [(row["payload"],)] if row else []
            return
        if "select payload from pramagent_traces where tenant_id" in sql_norm:
            tenant_id, limit = params
            rows = [r for r in self.db.traces.values() if r["tenant_id"] == tenant_id]
            self._rows = [(r["payload"],) for r in rows[: int(limit)]]
            return
        if "delete from pramagent_traces where tenant_id" in sql_norm:
            doomed = [tid for tid, r in self.db.traces.items()
                      if r["tenant_id"] == params[0]]
            for tid in doomed:
                del self.db.traces[tid]
            self.rowcount = len(doomed)
            return
        if "insert into pramagent_chain" in sql_norm:
            this_hash, prev_hash, payload = params
            if any(r["this_hash"] == this_hash for r in self.db.chain):
                self.rowcount = 0   # ON CONFLICT DO NOTHING
                return
            self.db.chain.append({
                "id": self.db.next_chain_id(),
                "this_hash": this_hash, "prev_hash": prev_hash,
                "payload": json.loads(payload),
            })
            self.rowcount = 1
            return
        if re.search(r"select this_hash from pramagent_chain order by id desc", sql_norm):
            self._rows = ([(self.db.chain[-1]["this_hash"],)]
                          if self.db.chain else [])
            return
        if "select id, this_hash, prev_hash, payload from pramagent_chain" in sql_norm:
            self._rows = [(r["id"], r["this_hash"], r["prev_hash"], r["payload"])
                          for r in sorted(self.db.chain, key=lambda r: r["id"])]
            return
        if "select this_hash, prev_hash, payload from pramagent_chain" in sql_norm:
            self._rows = [(r["this_hash"], r["prev_hash"], r["payload"])
                          for r in sorted(self.db.chain, key=lambda r: r["id"])]
            return
        if "update pramagent_chain set payload" in sql_norm:
            payload, this_hash, prev_hash, row_id = params
            for r in self.db.chain:
                if r["id"] == row_id:
                    r["payload"] = json.loads(payload)
                    r["this_hash"] = this_hash
                    r["prev_hash"] = prev_hash
                    self.rowcount = 1
                    return
            self.rowcount = 0
            return
        if "update pramagent_chain set prev_hash" in sql_norm:
            prev_hash, row_id = params
            for r in self.db.chain:
                if r["id"] == row_id:
                    r["prev_hash"] = prev_hash
                    self.rowcount = 1
                    return
            self.rowcount = 0
            return
        raise AssertionError(f"unexpected SQL: {sql}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeConnection:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.closed = 0
        self.autocommit = False

    def cursor(self):
        return _FakeCursor(self.db)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = 1


@pytest.fixture
def pg():
    db = _FakeDB()
    store = PostgresStore.from_dsn(
        "postgresql://unit-test", connect=lambda dsn: _FakeConnection(db))
    return store, db


def _trace(tenant: str, text: str, session: str = "s") -> TraceEvent:
    tr = TraceEvent(tenant_id=tenant, session_id=session, input_text=text)
    tr.this_hash = __import__("hashlib").sha256(
        f"{tenant}:{text}".encode()).hexdigest()
    return tr


# ───────────────────────────── store behaviour ────────────────────────────

def test_save_and_get_roundtrip(pg):
    store, _ = pg
    tr = _trace("acme", "hello world")
    store.save(tr)
    got = store.get(tr.this_hash)
    assert got is not None
    assert got["tenant_id"] == "acme"
    assert got["input_text"] == "hello world"


def test_tenant_isolation_in_listing(pg):
    store, _ = pg
    store.save(_trace("acme", "acme data"))
    store.save(_trace("globex", "globex data"))
    acme = store.list_for_tenant("acme")
    assert len(acme) == 1
    assert acme[0]["tenant_id"] == "acme"
    assert all(r["tenant_id"] == "globex" for r in store.list_for_tenant("globex"))


def test_erasure_deletes_only_target_tenant(pg):
    store, _ = pg
    store.save(_trace("erase-me", "subject data"))
    store.save(_trace("keeper", "other data"))
    deleted = store.delete_for_tenant("erase-me")
    assert deleted == 1
    assert store.list_for_tenant("erase-me") == []
    assert len(store.list_for_tenant("keeper")) == 1


# ───────────────────────────── hash chain ─────────────────────────────────

def test_chain_append_updates_head_and_verifies(pg):
    store, _ = pg
    h1, _ = store.append({"tenant_id": "t", "n": 1}, store.head)
    h2, _ = store.append({"tenant_id": "t", "n": 2}, h1)
    assert store.head == h2
    assert store.verify() == []          # no broken links


def test_chain_tamper_is_detected(pg):
    store, db = pg
    store.append({"tenant_id": "t", "n": 1}, store.head)
    db.chain[0]["payload"]["n"] = 999    # tamper directly in storage
    broken = store.verify()
    assert broken and broken[0]["reason"] == "hash mismatch"


def test_head_restored_on_reopen(pg):
    store, db = pg
    h1, _ = store.append({"tenant_id": "t", "n": 1}, store.head)
    # simulate process restart against the same database
    reopened = PostgresStore.from_dsn(
        "postgresql://unit-test", connect=lambda dsn: _FakeConnection(db))
    assert reopened.head == h1


# ───────────────────── erasure redacts the chain too ──────────────────────

def test_erasure_redacts_chain_payloads_and_still_verifies(pg):
    store, db = pg
    store.append({"tenant_id": "erase-me", "input_text": "SSN 123-45-6789",
                  "output_text": "ok"}, store.head)
    store.append({"tenant_id": "keeper", "input_text": "innocuous",
                  "output_text": "fine"}, store.head)
    store.save(_trace("erase-me", "SSN 123-45-6789"))

    store.delete_for_tenant("erase-me")

    chain_dump = json.dumps([r["payload"] for r in db.chain])
    assert "123-45-6789" not in chain_dump
    assert "innocuous" in chain_dump          # other tenant untouched
    assert store.verify() == []               # re-hashed, still verifies
    assert store.list_for_tenant("erase-me") == []


def test_redact_for_tenant_is_idempotent(pg):
    store, db = pg
    store.append({"tenant_id": "x", "input_text": "SSN 123-45-6789"}, store.head)
    assert store.redact_for_tenant("x") == 1
    assert store.redact_for_tenant("x") == 0
    assert store.verify() == []


# ───────────────────────────── failure modes ──────────────────────────────

def test_unreachable_postgres_raises_early():
    def refuse(dsn):
        raise ConnectionRefusedError("nope")

    with pytest.raises(PostgresUnavailable):
        PostgresStore.from_dsn("postgresql://down", connect=refuse)
