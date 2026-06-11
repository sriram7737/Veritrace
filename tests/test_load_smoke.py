"""Small deterministic load smoke tests.

These are not a substitute for k6/Locust/chaos testing, but they keep basic
concurrency regressions out of the main branch.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest

from pramagent import Pramagent
from pramagent.store import SQLiteStore


@pytest.mark.asyncio
async def test_concurrent_runs_preserve_trace_uniqueness_and_hash_chain():
    armor = Pramagent()

    responses = await asyncio.gather(*[
        armor.run(f"load smoke {i}", tenant_id="tenant", session_id=f"s{i % 5}")
        for i in range(40)
    ])

    call_ids = [r.trace.call_id for r in responses]
    assert len(set(call_ids)) == 40
    assert all(not r.blocked for r in responses)
    assert armor.audit.verify_chain()
    assert armor.observability.report()["total_calls"] == 40


def test_chain_survives_threaded_writers():
    """Genuinely threaded writers against one shared store (P1-5/T2-4).

    The single-event-loop smoke above can never preempt the head-read→append
    sequence, so it stays green even when the chain forks under threads —
    this is the test that actually exercises the serialized linkage
    derivation (BEGIN IMMEDIATE + re-read under the write lock). Before the
    fix two writers would read the same head, both insert with it, and
    verify_chain() would report tampering that is really a concurrency bug.
    """
    db = SQLiteStore(":memory:")

    def writer(i):
        asyncio.run(Pramagent(store=db, audit=db).run(
            f"thread-test-{i}", tenant_id="t1", session_id="s1"))

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(writer, range(64)))

    assert db.verify_chain()
    assert len(db.list_all()) == 64
    db.close()
