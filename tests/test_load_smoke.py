"""Small deterministic load smoke tests.

These are not a substitute for k6/Locust/chaos testing, but they keep basic
concurrency regressions out of the main branch.
"""
from __future__ import annotations

import asyncio

import pytest

from veritrace import Veritrace


@pytest.mark.asyncio
async def test_concurrent_runs_preserve_trace_uniqueness_and_hash_chain():
    armor = Veritrace()

    responses = await asyncio.gather(*[
        armor.run(f"load smoke {i}", tenant_id="tenant", session_id=f"s{i % 5}")
        for i in range(40)
    ])

    call_ids = [r.trace.call_id for r in responses]
    assert len(set(call_ids)) == 40
    assert all(not r.blocked for r in responses)
    assert armor.audit.verify_chain()
    assert armor.observability.report()["total_calls"] == 40
