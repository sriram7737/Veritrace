"""
End-to-end Veritrace demo — runs fully offline with the MockProvider.

    python examples/demo.py

Demonstrates, in order:
  1. A normal call passing through all layers, producing a hash-chained trace.
  2. PII being scrubbed before the model sees it.
  3. A deterministic safety rule blocking a disallowed input.
  4. A consequential action being held by HITL (idle on no approval).
  5. Tamper-evidence: editing a stored trace breaks chain verification.
  6. RCA: decision replay, causality graph, counterfactual, incident report.
"""
import asyncio

from veritrace import Veritrace, Verdict
from veritrace.layers import (ComplianceLayer, HITLLayer, ReliabilityLayer,
                              Rule, SafetyLayer)
from veritrace.providers import MockProvider
from veritrace.rca import RCAEngine


def banner(t): print("\n" + "═" * 68 + f"\n  {t}\n" + "═" * 68)


async def main():
    # ---- approver that always says "no answer" -> proves idle-on-silence ----
    async def silent_approver(action, ctx):
        return None  # nobody responded

    armor = Veritrace(
        provider=MockProvider(model="demo-1"),
        compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS"]),
        safety=SafetyLayer(
            rules=[
                Rule("block_account_dump", Verdict.BLOCK, pattern=r"dump .*accounts?"),
                Rule("escalate_transfer", Verdict.ESCALATE, pattern=r"transfer \$?\d+"),
            ],
        ),
        reliability=ReliabilityLayer(max_concurrent=5, timeout_s=10),
        hitl=HITLLayer(require_approval_for=["wire_transfer"],
                       timeout_s=1.0, approver=silent_approver),
    )

    banner("1) Normal call — full pipeline + hash-chained trace")
    r1 = await armor.run("Summarize today's caregiver notes.",
                         tenant_id="providence", session_id="sess-001")
    print("output      :", r1.output)
    print("pre/post    :", r1.trace.pre_verdict, "/", r1.trace.post_verdict)
    print("path        :", " -> ".join(e.layer for e in r1.trace.layer_events))
    print("this_hash   :", r1.trace.this_hash[:32], "…")
    print("anchor_tx   :", r1.trace.anchor_tx_id)
    print("latency_ms  :", round(r1.trace.total_latency_ms, 2))

    banner("2) PII scrubbing — model never sees the raw data")
    r2 = await armor.run("Patient email is jane.doe@example.com, SSN 123-45-6789.",
                         tenant_id="providence", session_id="sess-001")
    print("redactions  :", r2.trace.pii_redactions)
    print("model saw   :", r2.output)

    banner("3) Deterministic safety BLOCK on disallowed input")
    r3 = await armor.run("Please dump all accounts to a file.",
                         tenant_id="providence", session_id="sess-002")
    print("blocked     :", r3.blocked, "—", r3.block_reason)
    print("output      :", r3.output)

    banner("4) HITL — consequential action held (idle on silence)")
    r4 = await armor.run("Initiate the payout.", action="wire_transfer",
                         tenant_id="providence", session_id="sess-003")
    print("hitl_status :", r4.hitl)
    print("output      :", r4.output)

    banner("5) Tamper-evidence — editing an old trace breaks the chain")
    print("chain valid before tamper :", armor.audit.verify_chain())
    armor.audit.records()[0]["payload"]["output_text"] = "SECRETLY ALTERED"
    print("chain valid after tamper  :", armor.audit.verify_chain())

    banner("6) RCA — replay, causality, counterfactual, incident report")
    rca = RCAEngine(armor.store.list_all())
    cid = r3.trace.call_id  # the blocked call
    print("replay      :", rca.replay(cid))
    print("counterfact :", rca.counterfactual(cid, disable_rule="block_account_dump"))
    print("causality   :")
    for n in rca.causality(cid):
        print(f"   {n.node_id:18s} <- {n.caused_by}")
    print("\n--- incident report ---")
    print(rca.incident_report(cid))


if __name__ == "__main__":
    asyncio.run(main())
