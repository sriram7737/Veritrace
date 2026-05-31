"""
End-to-end Veritrace demo — runs fully offline with the MockProvider.
Set VERITRACE_PROVIDER=openai (+ OPENAI_API_KEY) to swap in a real OpenAI call.

    python examples/demo.py

Demonstrates the v0.3 "Production Guardrails MVP" live path:
  1. Normal call through all layers + hash-chained trace
  2. PII scrubbed before the model sees it
  3. Deterministic safety BLOCK on a malicious prompt
  4. ToolGuard BLOCK on a dangerous tool call (unregistered / bad args)
  5. HITL holds a consequential action (idle on silence)
  6. Tamper-evidence: editing a stored trace breaks chain verification
  7. RCA: replay, counterfactual, tool-call graph, incident report
"""
import asyncio

from veritrace import Veritrace, Verdict
from veritrace.layers import (ComplianceLayer, HITLLayer, ReliabilityLayer,
                              Rule, SafetyLayer, ToolGuardLayer, ToolPolicy)
from veritrace.layers.tool_guard import SideEffect
from veritrace.providers import MockProvider
from veritrace.rca import RCAEngine


def banner(t): print("\n" + "=" * 68 + f"\n  {t}\n" + "=" * 68)


async def main():
    async def silent_approver(action, ctx):
        return None

    guard = ToolGuardLayer(policies=[
        ToolPolicy(name="read_record", side_effect=SideEffect.READ, action=Verdict.ALLOW,
                   schema={"type": "object", "required": ["id"],
                           "properties": {"id": {"type": "string", "maxLength": 64}},
                           "additionalProperties": False}),
        ToolPolicy(name="wire_transfer", side_effect=SideEffect.PAYMENT, action=Verdict.ESCALATE,
                   schema={"type": "object", "required": ["amount_usd"],
                           "properties": {"amount_usd": {"type": "number", "maximum": 10000}}}),
    ])

    armor = Veritrace(
        provider=MockProvider(model="demo-1"),
        compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS"]),
        safety=SafetyLayer(rules=[
            Rule("block_account_dump", Verdict.BLOCK, pattern=r"dump .*accounts?"),
        ]),
        reliability=ReliabilityLayer(max_concurrent=5, timeout_s=10),
        hitl=HITLLayer(require_approval_for=["wire_transfer"], timeout_s=1.0,
                       approver=silent_approver),
        tool_guard=guard,
    )

    banner("1) Normal call — full pipeline + hash-chained trace")
    r1 = await armor.run("Summarize today's notes.", tenant_id="acme", session_id="s1")
    print("output    :", r1.output)
    print("this_hash :", r1.trace.this_hash[:32], "…")

    banner("2) PII scrubbing")
    r2 = await armor.run("Email jane@example.com, SSN 123-45-6789.",
                         tenant_id="acme", session_id="s1")
    print("redactions:", r2.trace.pii_redactions)

    banner("3) Malicious prompt BLOCKED by deterministic rule")
    r3 = await armor.run("Please dump all accounts.", tenant_id="acme", session_id="s2")
    print("blocked   :", r3.blocked, "—", r3.block_reason)

    banner("4) Dangerous tool call BLOCKED by ToolGuard")
    bad = armor.validate_tool("drop_table", {"x": 1}, tenant_id="acme")
    print("unregistered tool verdict:", bad.verdict.value, "—", bad.reason)
    bad2 = armor.validate_tool("read_record", {"id": "'; DROP TABLE users;--"},
                               tenant_id="acme")
    print("injection arg verdict    :", bad2.verdict.value, "—", bad2.reason)

    banner("5) HITL holds a consequential action (idle on silence)")
    r5 = await armor.run("Send the payout.", action="wire_transfer",
                         tenant_id="acme", session_id="s3")
    print("hitl      :", r5.hitl, "| output:", r5.output)

    banner("6) Tamper-evidence")
    print("chain valid before tamper:", armor.audit.verify_chain())
    armor.audit.records()[0]["payload"]["output_text"] = "ALTERED"
    print("chain valid after tamper :", armor.audit.verify_chain())

    banner("7) RCA — replay, counterfactual, tool-call graph, incident")
    rca = RCAEngine(armor.store.list_all())
    cid = r3.trace.call_id
    print("replay      :", rca.replay(cid)["derived_from_rules"])
    print("counterfact :", rca.counterfactual(cid, "block_account_dump")["counterfactual_verdict"])
    print("graph       :", rca.tool_call_graph(r5.trace.call_id))
    print("\n--- incident report ---")
    print(rca.incident_report(cid))


if __name__ == "__main__":
    asyncio.run(main())
