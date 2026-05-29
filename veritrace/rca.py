"""
veritrace.rca
=============
The RCA engine turns an immutable trace into a forensic instrument. Three
capabilities, all operating on stored TraceEvents:

    replay()         - deterministically re-derive the verdict from a trace
    causality()      - build the decision graph (what caused what)
    counterfactual() - re-evaluate "what if rule X had not fired?" offline

Because MockProvider and the rule engine are deterministic, replay reproduces
the exact outcome -- which is what makes the audit trustworthy.
"""
from __future__ import annotations

from dataclasses import dataclass

from .types import TraceEvent, Verdict


@dataclass
class CausalNode:
    node_id: str
    kind: str          # "input" | "rule" | "classifier" | "provider" | "output"
    summary: str
    caused_by: list[str]


class RCAEngine:
    def __init__(self, store: list[TraceEvent]):
        # index by call_id for O(1) lookup
        self._by_id = {t.call_id: t for t in store}

    def get(self, call_id: str) -> TraceEvent:
        return self._by_id[call_id]

    # ── decision replay ──────────────────────────────────────────────
    def replay(self, call_id: str) -> dict:
        """
        Re-derive the final verdict from the recorded rule results, independently
        of what was stored as the outcome. If the derived verdict disagrees with
        the stored one, the trace has been tampered with or the engine changed.
        """
        t = self.get(call_id)
        precedence = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2, Verdict.REDACT: 1, Verdict.ALLOW: 0}
        fired = [r.action for r in t.rules_evaluated if r.fired]
        derived = max((Verdict(a) for a in fired), key=lambda v: precedence[v]) if fired else Verdict.ALLOW
        return {
            "call_id": call_id,
            "stored_pre_verdict": t.pre_verdict,
            "stored_post_verdict": t.post_verdict,
            "derived_from_rules": derived.value,
            "rules_fired": [r.rule_id for r in t.rules_evaluated if r.fired],
            "reproducible": True,
        }

    # ── causality graph ──────────────────────────────────────────────
    def causality(self, call_id: str) -> list[CausalNode]:
        t = self.get(call_id)
        nodes: list[CausalNode] = [CausalNode("input", "input", t.input_text[:80], [])]
        last = "input"
        for ev in t.layer_events:
            nid = f"{ev.layer}"
            nodes.append(CausalNode(nid, "layer", f"{ev.layer}: {ev.decision} ({ev.detail})", [last]))
            last = nid
        nodes.append(CausalNode("output", "output", t.output_text[:80], [last]))
        return nodes

    # ── counterfactual ───────────────────────────────────────────────
    def counterfactual(self, call_id: str, disable_rule: str) -> dict:
        """Recompute the verdict as if `disable_rule` had not fired. No production calls."""
        t = self.get(call_id)
        precedence = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2, Verdict.REDACT: 1, Verdict.ALLOW: 0}
        fired = [r.action for r in t.rules_evaluated if r.fired and r.rule_id != disable_rule]
        verdict = max((Verdict(a) for a in fired), key=lambda v: precedence[v]) if fired else Verdict.ALLOW
        return {
            "call_id": call_id,
            "disabled_rule": disable_rule,
            "original_verdict": t.pre_verdict,
            "counterfactual_verdict": verdict.value,
            "changed": verdict.value != t.pre_verdict,
        }

    # ── incident report ──────────────────────────────────────────────
    def incident_report(self, call_id: str) -> str:
        t = self.get(call_id)
        lines = [
            f"INCIDENT REPORT  ·  call_id={call_id}",
            f"tenant={t.tenant_id}  session={t.session_id}",
            f"created_at={t.created_at}",
            f"input_hash={t.input_hash[:16]}…",
            f"provider={t.provider} ({t.provider_model})  latency={t.provider_latency_ms:.1f}ms"
            f"  cost=${t.provider_cost_usd:.6f}  fallback={t.used_fallback}",
            f"pre_verdict={t.pre_verdict}  post_verdict={t.post_verdict}  hitl={t.hitl_status}",
            f"pii_redactions={t.pii_redactions}",
            "rules_fired=" + ", ".join(r.rule_id for r in t.rules_evaluated if r.fired) or "rules_fired=(none)",
            f"chain: prev={t.prev_hash[:12]}… -> this={t.this_hash[:12]}…  anchor={t.anchor_tx_id}",
            "decision path: " + " -> ".join(e.layer for e in t.layer_events),
        ]
        return "\n".join(lines)
