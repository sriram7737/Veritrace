"""
veritrace.core
==============
The orchestrator. `Veritrace.run()` executes the full pipeline for one agent
call, in order, recording a LayerEvent at every step and emitting one immutable,
hash-chained TraceEvent. This is the single place the layer ordering lives.

Pipeline order (request path):
    Compliance.scrub -> Isolation(scope) -> Safety.pre -> Reliability.guard(
        Provider.complete ) -> Safety.post -> HITL.gate -> Trace.write(anchor)
"""
from __future__ import annotations

import hashlib
import time
from typing import Optional

from .audit import HashChainBackend
from .layers import (CircuitOpenError, ComplianceLayer, HITLLayer,
                     IsolationLayer, ObservabilityLayer,
                     ReliabilityLayer, SafetyLayer)
from .providers import BaseProvider, MockProvider
from .store import MemoryStore
from .types import (AgentResponse, HITLStatus, LayerEvent, TraceEvent, Verdict)


class Veritrace:
    def __init__(
        self,
        provider: Optional[BaseProvider] = None,
        compliance: Optional[ComplianceLayer] = None,
        safety: Optional[SafetyLayer] = None,
        reliability: Optional[ReliabilityLayer] = None,
        hitl: Optional[HITLLayer] = None,
        audit: Optional[HashChainBackend] = None,
        *,
        isolation: Optional["IsolationLayer"] = None,
        observability: Optional["ObservabilityLayer"] = None,
        store: Optional["MemoryStore"] = None,
    ):
        """Create a Veritrace orchestrator.

        Parameters beyond the core layers are provided as keyword-only
        arguments so callers can override them selectively.  If not supplied
        explicitly, sensible defaults are instantiated.  Pass a ``SQLiteStore``
        as both ``store`` and ``audit`` to persist traces and the hash chain
        to disk::

            from veritrace.store import SQLiteStore
            db = SQLiteStore("veritrace.db")
            armor = Veritrace(provider=..., store=db, audit=db)
        """
        self.provider = provider or MockProvider()
        self.compliance = compliance or ComplianceLayer()
        self.safety = safety or SafetyLayer()
        self.reliability = reliability or ReliabilityLayer()
        self.hitl = hitl or HITLLayer()
        self.audit = audit or HashChainBackend()
        self.isolation = isolation or IsolationLayer()
        self.observability = observability or ObservabilityLayer()
        self.store = store or MemoryStore()

    async def run(
        self,
        prompt: str,
        *,
        tenant_id: str = "default",
        session_id: str = "default",
        action: str = "respond",
    ) -> AgentResponse:
        # begin observability tracking
        self.observability.start_call()
        t_start = time.perf_counter()
        tr = TraceEvent(tenant_id=tenant_id, session_id=session_id, input_text=prompt)
        tr.input_hash = hashlib.sha256(prompt.encode()).hexdigest()

        def mark(layer: str, decision: str, detail: str, t0: float, **data):
            tr.layer_events.append(LayerEvent(
                layer=layer, decision=decision, detail=detail,
                latency_ms=(time.perf_counter() - t0) * 1000, data=data))

        # 1) Compliance ----------------------------------------------------
        t0 = time.perf_counter()
        clean, redactions = self.compliance.scrub(prompt)
        tr.pii_redactions = redactions
        mark("ComplianceLayer", "scrubbed", f"{len(redactions)} redaction(s)", t0)

        # 2) Isolation: size limits + injection heuristics + scope binding
        t0 = time.perf_counter()
        scope = f"{tenant_id}:{session_id}"
        try:
            iso_meta = await self.isolation.evaluate_input(
                clean, tenant_id=tenant_id, session_id=session_id)
            mark("IsolationLayer", "ok", scope, t0,
                 injection_hits=iso_meta["injection_hits"],
                 input_bytes=iso_meta["input_bytes"])
        except Exception as exc:
            # InputTooLarge or InjectionSuspected (or anything wrapping them).
            # Convert to a hard block; the trace still records the attempt.
            from .layers.isolation import (InjectionSuspected, InputTooLarge,
                                           IsolationViolation)
            reason = "isolation: " + (
                "injection suspected" if isinstance(exc, InjectionSuspected)
                else "input too large" if isinstance(exc, InputTooLarge)
                else "isolation violation" if isinstance(exc, IsolationViolation)
                else "isolation error"
            )
            mark("IsolationLayer", "blocked", str(exc)[:120], t0)
            response = self._finalize(tr, output="", blocked=True,
                                      reason=reason, t_start=t_start)
            self.observability.record_result(
                blocked=True, latency_ms=response.trace.total_latency_ms,
                block_reason=reason)
            return response

        # 3) Safety pre ----------------------------------------------------
        t0 = time.perf_counter()
        pre_verdict, pre_rules = self.safety.pre(clean)
        tr.pre_verdict = pre_verdict.value
        tr.rules_evaluated.extend(pre_rules)
        mark("SafetyLayer.pre", pre_verdict.value,
             ",".join(r.rule_id for r in pre_rules if r.fired) or "no rules fired", t0)

        if pre_verdict == Verdict.BLOCK:
            # record blocked request in observability and return immediately
            response = self._finalize(tr, output="", blocked=True,
                                      reason="blocked by input safety rule", t_start=t_start)
            self.observability.record_result(blocked=True, latency_ms=response.trace.total_latency_ms, block_reason="blocked by input safety rule")
            return response

        # 4) Reliability-guarded provider call -----------------------------
        t0 = time.perf_counter()
        try:
            result = await self.reliability.guard(lambda: self.provider.complete(clean))
            tr.provider = self.provider.name
            tr.provider_model = result.model
            tr.provider_cost_usd = result.cost_usd
            tr.provider_latency_ms = result.latency_ms
            tr.used_fallback = "fallback" in result.model
            output = result.text
            mark("ReliabilityLayer", "completed",
                 f"{self.provider.name}/{result.model}", t0)
        except CircuitOpenError:
            response = self._finalize(tr, output="[service temporarily unavailable]",
                                      blocked=True, reason="circuit breaker open", t_start=t_start)
            self.observability.record_result(blocked=True, latency_ms=response.trace.total_latency_ms, block_reason="circuit breaker open")
            return response
        except Exception as e:  # graceful degradation
            mark("ReliabilityLayer", "degraded", str(e)[:80], t0)
            response = self._finalize(tr, output="[safe default: unable to complete]",
                                      blocked=True, reason=f"provider error: {e}", t_start=t_start)
            self.observability.record_result(blocked=True, latency_ms=response.trace.total_latency_ms, block_reason=f"provider error: {e}")
            return response

        # 5) Safety post ---------------------------------------------------
        t0 = time.perf_counter()
        post_verdict, post_rules = self.safety.post(output)
        tr.post_verdict = post_verdict.value
        tr.rules_evaluated.extend(post_rules)
        mark("SafetyLayer.post", post_verdict.value,
             ",".join(r.rule_id for r in post_rules if r.fired) or "no rules fired", t0)
        if post_verdict == Verdict.BLOCK:
            output = "[output withheld by safety rule]"
        elif post_verdict == Verdict.REDACT:
            output, _ = self.compliance.scrub(output)

        # 5b) Output size cap ---------------------------------------------
        output, was_truncated = self.isolation.truncate_output(output)
        if was_truncated:
            mark("IsolationLayer.cap_output", "truncated",
                 f"capped at {self.isolation.max_output_bytes}B", time.perf_counter())

        # 6) HITL ----------------------------------------------------------
        t0 = time.perf_counter()
        status = await self.hitl.gate(action, {"tenant": tenant_id, "output_preview": output[:120]})
        tr.hitl_status = status.value
        mark("HITLLayer", status.value, f"action={action}", t0)
        if status in (HITLStatus.DENIED, HITLStatus.IDLE) and self.hitl.is_consequential(action):
            output = "[action not executed — awaiting/declined human approval]"

        response = self._finalize(tr, output=output, blocked=False, reason="", t_start=t_start)
        # update observability metrics on successful completion
        self.observability.record_result(blocked=False, latency_ms=response.trace.total_latency_ms)
        return response

    def _finalize(self, tr: TraceEvent, *, output: str, blocked: bool,
                  reason: str, t_start: float) -> AgentResponse:
        tr.output_text = output
        tr.total_latency_ms = (time.perf_counter() - t_start) * 1000
        # hash-chain the trace (exclude volatile hash fields from the hashed payload)
        payload = tr.to_dict()
        for k in ("this_hash", "anchor_tx_id", "prev_hash"):
            payload.pop(k, None)
        tr.prev_hash = self.audit.head
        tr.this_hash, tr.anchor_tx_id = self.audit.append(payload, tr.prev_hash)
        self.store.save(tr)
        return AgentResponse(output=output, trace=tr, blocked=blocked, block_reason=reason)
