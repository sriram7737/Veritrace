"""Tests for RCA complex-agent support: tool-call graphs + multi-rule counterfactuals."""
import asyncio
import pytest

from pramagent import Pramagent, Verdict
from pramagent.layers import SafetyLayer, Rule, ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect
from pramagent.providers import MockProvider
from pramagent.rca import RCAEngine


def run(coro):
    return asyncio.run(coro)


def _armor_with_tool():
    guard = ToolGuardLayer(policies=[
        ToolPolicy(name="read_db", side_effect=SideEffect.READ, action=Verdict.ALLOW,
                   schema={"type": "object", "properties": {}}),
        ToolPolicy(name="wire", side_effect=SideEffect.PAYMENT, action=Verdict.ESCALATE,
                   schema={"type": "object", "properties": {}}),
    ])
    return Pramagent(provider=MockProvider(), tool_guard=guard,
                     safety=SafetyLayer(rules=[
                         Rule("block_dump", Verdict.BLOCK, pattern=r"dump .*accounts?"),
                     ]))


def test_tool_call_graph_records_nodes():
    armor = _armor_with_tool()
    r = run(armor.run("do a payment", tool_name="wire", tool_arguments={},
                      action="wire", tenant_id="t", session_id="s"))
    rca = RCAEngine(armor.store.list_all())
    g = rca.tool_call_graph(r.trace.call_id)
    assert len(g["nodes"]) >= 1
    assert g["nodes"][0]["side_effect"] == "payment"
    # ESCALATE is a branch point
    assert any(b["verdict"] == "escalate" for b in g["branches"])
    assert g["is_linear"] is False


def test_tool_call_graph_linear_when_allowed():
    armor = _armor_with_tool()
    r = run(armor.run("read it", tool_name="read_db", tool_arguments={},
                      action="respond", tenant_id="t", session_id="s"))
    rca = RCAEngine(armor.store.list_all())
    g = rca.tool_call_graph(r.trace.call_id)
    assert g["is_linear"] is True
    assert g["branches"] == []


def test_multi_rule_counterfactual():
    armor = _armor_with_tool()
    r = run(armor.run("please dump all accounts", tenant_id="t", session_id="s"))
    rca = RCAEngine(armor.store.list_all())
    cf = rca.multi_rule_counterfactual(r.trace.call_id, ["block_dump"])
    assert cf["counterfactual_verdict"] == "allow"
    assert cf["changed"] is True


def test_critical_path_lists_decisive_layers():
    armor = _armor_with_tool()
    r = run(armor.run("please dump all accounts", tenant_id="t", session_id="s"))
    rca = RCAEngine(armor.store.list_all())
    path = rca.critical_path(r.trace.call_id)
    assert any("Safety" in p for p in path)
