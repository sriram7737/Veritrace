"""Tests for SQLiteStore: persistence, chain integrity, and survival across restarts."""
import asyncio
import os
import tempfile

from veritrace import Veritrace, Verdict
from veritrace.layers import ComplianceLayer, SafetyLayer, Rule
from veritrace.providers import MockProvider
from veritrace.store import SQLiteStore


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_armor(db_path):
    """Build a Veritrace instance backed by SQLite at the given path."""
    db = SQLiteStore(db_path)
    return Veritrace(
        provider=MockProvider(),
        safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"forbidden")]),
        compliance=ComplianceLayer(),
        store=db,
        audit=db,
    ), db


def test_sqlite_saves_and_retrieves():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        r = run(armor.run("hello", tenant_id="t", session_id="s"))
        retrieved = db.get(r.trace.call_id)
        assert retrieved.call_id == r.trace.call_id
        assert retrieved.output_text == r.trace.output_text
        assert len(db.list_all()) == 1
    finally:
        db.close()
        os.unlink(path)


def test_sqlite_survives_restart():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        # session 1: write a trace
        armor1, db1 = _make_armor(path)
        r = run(armor1.run("remember this", tenant_id="a", session_id="1"))
        cid = r.trace.call_id
        chain_head = db1.head
        db1.close()

        # session 2: reopen the same file
        db2 = SQLiteStore(path)
        assert len(db2.list_all()) == 1
        retrieved = db2.get(cid)
        assert retrieved.input_text == "remember this"
        assert db2.head == chain_head          # chain head restored
        assert db2.verify_chain()              # chain still valid
        db2.close()
    finally:
        os.unlink(path)


def test_sqlite_chain_integrity():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        run(armor.run("a")); run(armor.run("b")); run(armor.run("c"))
        assert len(db.list_all()) == 3
        assert db.verify_chain()
        db.close()
    finally:
        os.unlink(path)


def test_sqlite_pii_scrubbing_persisted():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        r = run(armor.run("email me at a@b.com", tenant_id="t", session_id="s"))
        db.close()
        # reopen and verify PII was scrubbed in the persisted trace
        db2 = SQLiteStore(path)
        t = db2.get(r.trace.call_id)
        assert "email" in t.pii_redactions
        assert "a@b.com" not in t.output_text
        db2.close()
    finally:
        os.unlink(path)


def test_sqlite_multiple_tenants_isolated():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        run(armor.run("alpha", tenant_id="bank", session_id="s1"))
        run(armor.run("beta", tenant_id="hospital", session_id="s2"))
        assert len(db.list_by_tenant("bank")) == 1
        assert len(db.list_by_tenant("hospital")) == 1
        assert len(db.list_all()) == 2
        db.close()
    finally:
        os.unlink(path)
