"""
pramagent.core
==============
The orchestrator. Pramagent.run() executes the full pipeline for one agent
call, in order, recording a LayerEvent at every step and emitting one immutable,
hash-chained TraceEvent. This is the single place the layer ordering lives.

Pipeline order (request path):
    Compliance.scrub -> Isolation(scope) -> Safety.pre -> ToolGuard(action) ->
    Reliability.guard( Provider.complete ) -> Safety.post -> HITL.gate ->
    Trace.write(anchor)

OTel spans are created per layer so any distributed trace backend (Jaeger,
Honeycomb, Datadog) gets full latency breakdown.  Pass incoming HTTP headers to
span_from_headers() so the pipeline is subordinate to the caller's trace.

Tool calls validated via validate_tool() go through ToolGuardLayer before
any side effect is executed. Unregistered tools are blocked by default.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Optional

from .audit import HashChainBackend
from .layers import (CircuitOpenError, ComplianceLayer, HITLLayer,
                     IsolationLayer, ObservabilityLayer,
                     ReliabilityLayer, SafetyLayer, ToolGuardLayer, ToolPolicy)
from .layers.tool_guard import ToolDecision
from .providers import BaseProvider, MockProvider
from .store import MemoryStore
from .telemetry import trace_layer, span_from_headers
from .types import (AgentResponse, HITLStatus, LayerEvent, TraceEvent, Verdict)

log = logging.getLogger(__name__)


class Pramagent:
    def __init__(
        self,
        provider=None,
        compliance=None,
        safety=None,
        reliability=None,
        hitl=None,
        audit=None,
        *,
        isolation=None,
        observability=None,
        store=None,
        tool_guard=None,
        consent=None,
        consent_purpose: str = "service_provision",
    ):
        """Create a Pramagent orchestrator.

        Pass a SQLiteStore as both store and audit to persist traces to disk::

            from pramagent.store import SQLiteStore
            db = SQLiteStore("pramagent.db")
            armor = Pramagent(provider=..., store=db, audit=db)

        Pass incoming request headers to run() for W3C trace propagation::

            resp = await armor.run(prompt, tenant_id=..., trace_headers=request.headers)
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
        # Default: block all unregistered tool calls. Callers register tools
        # via tool_guard=ToolGuardLayer(policies=[...]) or post-construction
        # via armor.tool_guard.register(policy).
        self.tool_guard = tool_guard or ToolGuardLayer(default_verdict=Verdict.BLOCK)
        # Optional consent gate (GDPR Art. 5(1)(b)/7). When a ConsentRegistry
        # is supplied, run() refuses to process unless consent for the
        # tenant/subject covers `consent_purpose`. Absence of a registry
        # keeps the previous behaviour (no consent enforcement).
        self.consent = consent
        self.consent_purpose = consent_purpose

    def validate_tool(
        self,
        tool_name: str,
        arguments: dict,
        *,
        tenant_id: str = "default",
        session_id: str = "default",
        action_label: str = "tool_call",
    ) -> ToolDecision:
        """Validate a proposed tool call before execution.

        Returns a ToolDecision whose .verdict is ALLOW, ESCALATE, or BLOCK.
        BLOCK means must not execute. ESCALATE means requires human approval.

        Example::

            decision = armor.validate_tool(
                "send_payment",
                {"amount_usd": 500, "account": "acct-123"},
                tenant_id="acme", session_id="s1", action_label="wire_transfer")
            if decision.verdict == Verdict.BLOCK:
                raise PermissionError(decision.reason)
        """
        return self.tool_guard.evaluate(
            tool_name, arguments,
            tenant_id=tenant_id,
            session_id=session_id,
            action_label=action_label,
        )

    async def run(
        self,
        prompt: str,
        *,
        tenant_id: str = "default",
        session_id: str = "default",
        action: str = "respond",
        tool_name=None,
        tool_arguments=None,
        trace_headers: Optional[dict] = None,
        subject_id: Optional[str] = None,
    ) -> AgentResponse:
        """Run one agent call through the full trust pipeline.

        Parameters
        ----------
        trace_headers : dict, optional
            Incoming HTTP headers. If present, the W3C traceparent is extracted
            and used as the parent span for the entire pipeline, enabling
            distributed tracing across service boundaries.

        If tool_name is provided the ToolGuardLayer is consulted before the
        provider call. A BLOCK verdict short-circuits the pipeline immediately;
        an ESCALATE verdict is recorded in the trace.
        """
        self.observability.start_call()
        t_start = time.perf_counter()
        # input_text is filled with the SCRUBBED copy after the compliance
        # pass — raw PII must never reach the persisted trace or the audit
        # chain (GDPR Art. 5(1)(c) data minimization). input_hash still
        # covers the original bytes so the caller can prove what was sent.
        tr = TraceEvent(tenant_id=tenant_id, session_id=session_id)
        tr.input_hash = hashlib.sha256(prompt.encode()).hexdigest()

        def mark(layer, decision, detail, t0, **data):
            tr.layer_events.append(LayerEvent(
                layer=layer, decision=decision, detail=detail,
                latency_ms=(time.perf_counter() - t0) * 1000, data=data))

        with span_from_headers(trace_headers or {}, span_name="pramagent.request") as root_span:
            root_span.set_attribute("tenant.id", tenant_id)
            root_span.set_attribute("session.id", session_id)
            root_span.set_attribute("action", action)

            # 0) Consent gate (GDPR Art. 5(1)(b) purpose limitation / Art. 7).
            # Enforced only when a ConsentRegistry is configured. The subject
            # defaults to the session id when no explicit subject_id is given.
            if self.consent is not None:
                t0 = time.perf_counter()
                subject = subject_id or session_id
                allowed = self.consent.check(tenant_id, subject, self.consent_purpose)
                mark("ConsentGate", "ok" if allowed else "blocked",
                     f"purpose={self.consent_purpose}", t0)
                if not allowed:
                    reason = (f"no consent on file for purpose "
                              f"'{self.consent_purpose}'")
                    root_span.set_attribute("blocked", True)
                    root_span.set_attribute("block_reason", reason)
                    response = self._finalize(tr, output="", blocked=True,
                                              reason=reason, t_start=t_start)
                    self.observability.record_result(
                        blocked=True,
                        latency_ms=response.trace.total_latency_ms,
                        block_reason=reason)
                    return response

            # 1) Compliance
            t0 = time.perf_counter()
            with trace_layer("ComplianceLayer") as span:
                clean, redactions = self.compliance.scrub(prompt)
                span.set_attribute("pii.redaction_count", len(redactions))
            tr.pii_redactions = redactions
            tr.input_text = clean   # persist only the scrubbed copy
            mark("ComplianceLayer", "scrubbed", f"{len(redactions)} redaction(s)", t0)

            # 2) Isolation: size limits + injection heuristics + scope binding
            t0 = time.perf_counter()
            scope = f"{tenant_id}:{session_id}"
            with trace_layer("IsolationLayer", attributes={"scope": scope}) as span:
                try:
                    iso_meta = await self.isolation.evaluate_input(
                        clean, tenant_id=tenant_id, session_id=session_id)
                    span.set_attribute("input.bytes", iso_meta["input_bytes"])
                    span.set_attribute("injection_hits", len(iso_meta["injection_hits"]))
                    mark("IsolationLayer", "ok", scope, t0,
                         injection_hits=iso_meta["injection_hits"],
                         input_bytes=iso_meta["input_bytes"])
                except Exception as exc:
                    from .layers.isolation import (InjectionSuspected, InputTooLarge,
                                                   IsolationViolation)
                    reason = "isolation: " + (
                        "injection suspected" if isinstance(exc, InjectionSuspected)
                        else "input too large" if isinstance(exc, InputTooLarge)
                        else "isolation violation" if isinstance(exc, IsolationViolation)
                        else "isolation error"
                    )
                    span.set_attribute("blocked", True)
                    span.set_attribute("block_reason", reason)
                    mark("IsolationLayer", "blocked", str(exc)[:120], t0)
                    response = self._finalize(tr, output="", blocked=True,
                                              reason=reason, t_start=t_start)
                    self.observability.record_result(
                        blocked=True, latency_ms=response.trace.total_latency_ms,
                        block_reason=reason)
                    return response

            # 3) Safety pre
            t0 = time.perf_counter()
            with trace_layer("SafetyLayer.pre") as span:
                pre_verdict, pre_rules = self.safety.pre(clean)
                span.set_attribute("verdict", pre_verdict.value)
                fired = [r.rule_id for r in pre_rules if r.fired]
                span.set_attribute("rules_fired", ",".join(fired))
            tr.pre_verdict = pre_verdict.value
            tr.rules_evaluated.extend(pre_rules)
            mark("SafetyLayer.pre", pre_verdict.value,
                 ",".join(r.rule_id for r in pre_rules if r.fired) or "no rules fired", t0)

            if pre_verdict == Verdict.BLOCK:
                response = self._finalize(tr, output="", blocked=True,
                                          reason="blocked by input safety rule", t_start=t_start)
                self.observability.record_result(blocked=True,
                    latency_ms=response.trace.total_latency_ms,
                    block_reason="blocked by input safety rule")
                return response

            # 3b) ToolGuard — validate proposed tool call before any side effect
            if tool_name is not None:
                t0 = time.perf_counter()
                args = tool_arguments or {}
                with trace_layer("ToolGuardLayer", attributes={"tool": tool_name}) as span:
                    td = await self.tool_guard.evaluate_async(
                        tool_name, args,
                        tenant_id=tenant_id, session_id=session_id,
                        action_label=action,
                    )
                    span.set_attribute("verdict", td.verdict.value)
                    span.set_attribute("side_effect", td.side_effect)
                    span.set_attribute("injection_findings",
                                       len(td.injection_findings))
                mark("ToolGuardLayer", td.verdict.value,
                     f"{tool_name}: {td.reason}", t0,
                     side_effect=td.side_effect, decision_id=td.decision_id)
                if td.verdict == Verdict.BLOCK:
                    reason = f"tool blocked by policy: {td.reason}"
                    response = self._finalize(tr, output="", blocked=True,
                                              reason=reason, t_start=t_start)
                    self.observability.record_result(blocked=True,
                        latency_ms=response.trace.total_latency_ms, block_reason=reason)
                    return response
                if td.verdict == Verdict.ESCALATE:
                    # ESCALATE → HITL: the tool requires human approval before
                    # any side effect. Propose-and-wait; on DENIED or IDLE
                    # (silence is never consent) the call does not proceed.
                    hitl_action = f"tool:{tool_name}"
                    t0 = time.perf_counter()
                    with trace_layer("HITLLayer",
                                     attributes={"action": hitl_action}) as span:
                        status = await self.hitl.propose(hitl_action, {
                            "tenant": tenant_id,
                            "tool_name": tool_name,
                            "side_effect": td.side_effect,
                            "reason": td.reason,
                        })
                        span.set_attribute("hitl.status", status.value)
                    tr.hitl_status = status.value
                    mark("HITLLayer", status.value,
                         f"tool escalation: {tool_name} ({td.reason})", t0,
                         tool_name=tool_name, decision_id=td.decision_id)
                    if status != HITLStatus.APPROVED:
                        reason = (f"tool '{tool_name}' requires human approval: "
                                  + ("denied" if status == HITLStatus.DENIED
                                     else "no response"))
                        response = self._finalize(
                            tr, output="[action not executed - awaiting/declined human approval]",
                            blocked=True, reason=reason, t_start=t_start)
                        self.observability.record_result(blocked=True,
                            latency_ms=response.trace.total_latency_ms,
                            block_reason=reason)
                        return response

            # 4) Reliability-guarded provider call
            t0 = time.perf_counter()
            with trace_layer("ReliabilityLayer") as span:
                try:
                    result = await self.reliability.guard(lambda: self.provider.complete(clean))
                    tr.provider = self.provider.name
                    tr.provider_model = result.model
                    tr.provider_cost_usd = result.cost_usd
                    tr.provider_latency_ms = result.latency_ms
                    tr.provider_prompt_tokens = getattr(result, "prompt_tokens", 0)
                    tr.provider_completion_tokens = getattr(result, "completion_tokens", 0)
                    tr.used_fallback = bool(getattr(result, "used_fallback", False))
                    output = result.text
                    span.set_attribute("provider", self.provider.name)
                    span.set_attribute("model", result.model)
                    span.set_attribute("cost_usd", result.cost_usd)
                    mark("ReliabilityLayer", "completed",
                         f"{self.provider.name}/{result.model}", t0)
                except CircuitOpenError:
                    span.set_attribute("circuit_open", True)
                    response = self._finalize(
                        tr, output="[service temporarily unavailable]",
                        blocked=True, reason="circuit breaker open", t_start=t_start)
                    self.observability.record_result(blocked=True,
                        latency_ms=response.trace.total_latency_ms,
                        block_reason="circuit breaker open")
                    return response
                except Exception as e:
                    span.set_attribute("error", str(e))
                    # Exception detail stays in the log and the tenant-scoped
                    # trace; the response body gets a generic reason so
                    # provider internals never leak to the caller.
                    log.warning("provider call failed (tenant=%s session=%s): %r",
                                tenant_id, session_id, e)
                    mark("ReliabilityLayer", "degraded", str(e)[:80], t0)
                    response = self._finalize(
                        tr, output="[safe default: unable to complete]",
                        blocked=True, reason="provider error", t_start=t_start)
                    self.observability.record_result(blocked=True,
                        latency_ms=response.trace.total_latency_ms,
                        block_reason="provider error")
                    return response

            # 5) Safety post
            t0 = time.perf_counter()
            with trace_layer("SafetyLayer.post") as span:
                post_verdict, post_rules = self.safety.post(output)
                span.set_attribute("verdict", post_verdict.value)
            tr.post_verdict = post_verdict.value
            tr.rules_evaluated.extend(post_rules)
            mark("SafetyLayer.post", post_verdict.value,
                 ",".join(r.rule_id for r in post_rules if r.fired) or "no rules fired", t0)
            if post_verdict == Verdict.BLOCK:
                output = "[output withheld by safety rule]"
            elif post_verdict == Verdict.REDACT:
                output, _ = self.compliance.scrub(output)

            # 5b) Output size cap
            output, was_truncated = self.isolation.truncate_output(output)
            if was_truncated:
                mark("IsolationLayer.cap_output", "truncated",
                     f"capped at {self.isolation.max_output_bytes}B", time.perf_counter())

            # 5c) ToolGuard output validation — exfiltration scan (AWS keys,
            # private keys, JWTs, …) on the provider output, plus output
            # schema/size checks when this call was a registered tool.
            t0 = time.perf_counter()
            with trace_layer("ToolGuardLayer.validate_output") as span:
                ov = self.tool_guard.validate_output(
                    tool_name if tool_name is not None else "__provider__",
                    output, tenant_id=tenant_id, session_id=session_id)
                span.set_attribute("output.ok", ov.ok)
            mark("ToolGuardLayer.validate_output",
                 "ok" if ov.ok else "withheld", ov.reason, t0)
            if not ov.ok:
                output = "[output withheld by tool output validation]"

            # 6) HITL
            t0 = time.perf_counter()
            with trace_layer("HITLLayer", attributes={"action": action}) as span:
                status = await self.hitl.gate(
                    action, {"tenant": tenant_id, "output_preview": output[:120]})
                span.set_attribute("hitl.status", status.value)
            tr.hitl_status = status.value
            mark("HITLLayer", status.value, f"action={action}", t0)
            if status in (HITLStatus.DENIED, HITLStatus.IDLE) and self.hitl.is_consequential(action):
                output = "[action not executed - awaiting/declined human approval]"

            response = self._finalize(tr, output=output, blocked=False, reason="", t_start=t_start)
            root_span.set_attribute("total_latency_ms", response.trace.total_latency_ms)
            root_span.set_attribute("blocked", False)
            self.observability.record_result(blocked=False, latency_ms=response.trace.total_latency_ms)
            return response

    def _finalize(self, tr, *, output, blocked, reason, t_start):
        # The caller receives `output` as-is; the durable record (trace +
        # audit chain) keeps only the scrubbed copy, mirroring input_text.
        scrubbed_output, _ = self.compliance.scrub(output)
        tr.output_text = scrubbed_output
        tr.total_latency_ms = (time.perf_counter() - t_start) * 1000
        payload = tr.to_dict()
        for k in (
            "this_hash",
            "anchor_tx_id",
            "anchor_block_number",
            "anchor_metadata",
            "prev_hash",
        ):
            payload.pop(k, None)
        tr.prev_hash = self.audit.head
        tr.this_hash, tr.anchor_tx_id = self.audit.append(payload, tr.prev_hash)
        anchor_receipt = getattr(self.audit, "last_anchor", None)
        if anchor_receipt is not None:
            tr.anchor_block_number = int(getattr(anchor_receipt, "block_number", 0) or 0)
            if hasattr(anchor_receipt, "to_dict"):
                tr.anchor_metadata = anchor_receipt.to_dict()
        self.store.save(tr)
        return AgentResponse(output=output, trace=tr, blocked=blocked, block_reason=reason)
