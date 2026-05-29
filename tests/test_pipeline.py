"""Minimal but real test suite. Run with: pytest -q"""
import asyncio

from veritrace import Veritrace, Verdict
from veritrace.layers import ComplianceLayer, HITLLayer, Rule, SafetyLayer
from veritrace.providers import MockProvider
from veritrace.rca import RCAEngine


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_normal_call_produces_chained_trace():
    armor = Veritrace(provider=MockProvider())
    r = run(armor.run("hi", tenant_id="t", session_id="s"))
    assert r.output
    assert r.trace.this_hash and r.trace.prev_hash == "0" * 64
    assert armor.audit.verify_chain()


def test_pii_is_scrubbed():
    armor = Veritrace(provider=MockProvider(), compliance=ComplianceLayer())
    r = run(armor.run("email me at a@b.com"))
    assert "email" in r.trace.pii_redactions
    assert "a@b.com" not in r.output


def test_block_rule_stops_call():
    armor = Veritrace(
        provider=MockProvider(),
        safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"forbidden")]),
    )
    r = run(armor.run("this is forbidden"))
    assert r.blocked and r.trace.pre_verdict == "block"


def test_hitl_idle_on_silence():
    async def no_answer(a, c): return None
    armor = Veritrace(
        provider=MockProvider(),
        hitl=HITLLayer(require_approval_for=["pay"], timeout_s=0.5, approver=no_answer),
    )
    r = run(armor.run("pay now", action="pay"))
    assert r.hitl == "idle"


def test_tamper_breaks_chain():
    armor = Veritrace(provider=MockProvider())
    run(armor.run("a")); run(armor.run("b"))
    assert armor.audit.verify_chain()
    armor.audit.records()[0]["payload"]["output_text"] = "x"
    assert not armor.audit.verify_chain()


def test_rca_replay_reproducible():
    armor = Veritrace(
        provider=MockProvider(),
        safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"nope")]),
    )
    r = run(armor.run("nope"))
    rca = RCAEngine(armor.store.list_all())
    rep = rca.replay(r.trace.call_id)
    assert rep["derived_from_rules"] == "block"
    assert rep["reproducible"]
