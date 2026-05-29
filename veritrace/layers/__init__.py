"""
veritrace.layers
================
Trust layers. Each layer is small, single-responsibility, and independently
testable.

Layers shipped here:

    ComplianceLayer    - PII detection + redaction (context-guarded patterns)
    SafetyLayer        - pre/post classifier + deterministic rule engine
    ReliabilityLayer   - semaphore-bounded concurrency + timeout + circuit breaker
    HITLLayer          - propose-and-wait gateway; idle on silence
    IsolationLayer     - tenant-scoped memory + injection heuristics + size limits
                         (see veritrace.layers.isolation)
    ObservabilityLayer - call counters, block rate, p50/p95 latency
                         (see veritrace.layers.observability)

RCAEngine is in veritrace.rca; the audit chain is in veritrace.audit.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from ..types import HITLStatus, RuleResult, Verdict

# Real implementations live in their own modules to keep this file small.
from .isolation import (IsolationLayer, IsolationViolation, InputTooLarge,
                        InjectionSuspected)
from .observability import ObservabilityLayer



# ───────────────────────────── ComplianceLayer ─────────────────────────────
class ComplianceLayer:
    """
    Detects and redacts PII before it reaches any LLM.

    Two pattern classes:

      * DEFAULT_PATTERNS  -- high-precision shapes (email, SSN, IBAN, …). The
        shape itself is distinctive, so the whole match is redacted wherever it
        appears.

      * DEFAULT_CONTEXTUAL -- ambiguous shapes (a bare 9-digit number, an ISO
        date). These are redacted ONLY when a context keyword appears within
        CONTEXT_WINDOW characters. This matters: a naive `\\d{9}` redacts every
        order id, and a naive ISO-date pattern redacts every event timestamp --
        a SILENT failure that quietly degrades agent quality without any error.
        Requiring nearby context keeps recall on real PII while eliminating the
        false positives.

    Both sets are fully overridable via the constructor.
    """

    DEFAULT_PATTERNS = {
        "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "account": r"\bacct[-_ ]?\d{6,}\b",
        "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",   # distinctive enough to keep
    }

    # label -> (value_pattern, [context_keywords])
    DEFAULT_CONTEXTUAL = {
        "routing_number": (r"\b\d{9}\b", ["routing", "aba", "rtn"]),
        "dob": (r"\b\d{4}-\d{2}-\d{2}\b", ["dob", "d.o.b", "birth", "born"]),
    }

    CONTEXT_WINDOW = 32  # chars on each side of a candidate to scan for a keyword

    def __init__(self, standards: list[str] | None = None,
                 patterns: dict[str, str] | None = None,
                 contextual_patterns: dict[str, tuple[str, list[str]]] | None = None,
                 enabled: bool = True):
        self.standards = standards or ["GDPR", "HIPAA"]
        self.patterns = {k: re.compile(v, re.IGNORECASE)
                         for k, v in (patterns or self.DEFAULT_PATTERNS).items()}
        ctx = contextual_patterns if contextual_patterns is not None else self.DEFAULT_CONTEXTUAL
        self.contextual_patterns = {
            k: (re.compile(p, re.IGNORECASE), [kw.lower() for kw in kws])
            for k, (p, kws) in ctx.items()
        }
        self.enabled = enabled

    def scrub(self, text: str) -> tuple[str, list[str]]:
        if not self.enabled:
            return text, []
        redactions: list[str] = []
        out = text

        # 1) high-precision patterns: redact the whole match wherever it appears
        for label, rx in self.patterns.items():
            def _sub(m, _label=label):
                redactions.append(_label)
                return f"[REDACTED:{_label.upper()}]"
            out = rx.sub(_sub, out)

        # 2) contextual patterns: redact only when a context keyword is nearby
        for label, (rx, keywords) in self.contextual_patterns.items():
            src = out  # stable snapshot; re.sub scans this and returns a new string
            def _ctx(m, _label=label, _kw=keywords, _src=src):
                s, e = m.start(), m.end()
                window = _src[max(0, s - self.CONTEXT_WINDOW): e + self.CONTEXT_WINDOW].lower()
                if any(k in window for k in _kw):
                    redactions.append(_label)
                    return f"[REDACTED:{_label.upper()}]"
                return m.group(0)
            out = rx.sub(_ctx, src)

        return out, redactions


# ─────────────────────────────── SafetyLayer ───────────────────────────────
@dataclass
class Rule:
    """
    A single deterministic rule. `fn` receives the text and returns True if the
    rule fires. When a rule fires its `action` is applied. Rules sit OUTSIDE the
    model and cannot be overridden by model output -- that is the whole point.
    """
    rule_id: str
    action: Verdict
    pattern: Optional[str] = None
    fn: Optional[Callable[[str], bool]] = None
    detail: str = ""
    _rx: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if self.pattern:
            self._rx = re.compile(self.pattern, re.IGNORECASE)

    def evaluate(self, text: str) -> RuleResult:
        fired = False
        if self._rx is not None:
            fired = bool(self._rx.search(text))
        elif self.fn is not None:
            fired = bool(self.fn(text))
        return RuleResult(rule_id=self.rule_id, fired=fired,
                          action=self.action if fired else Verdict.ALLOW,
                          detail=self.detail if fired else "")


class SafetyLayer:
    """
    Two-pass safety. `pre()` screens input; `post()` screens output. A classifier
    callable can be supplied for ML-based screening; the deterministic rule engine
    always runs and has final veto authority (BLOCK > ESCALATE > REDACT > ALLOW).
    """

    _PRECEDENCE = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2, Verdict.REDACT: 1, Verdict.ALLOW: 0}

    def __init__(self, rules: list[Rule] | None = None,
                 classifier: Optional[Callable[[str], Verdict]] = None):
        self.rules = rules or []
        self.classifier = classifier

    def _combine(self, results: list[RuleResult], clf: Optional[Verdict]) -> Verdict:
        verdicts = [r.action for r in results if r.fired]
        if clf is not None:
            verdicts.append(clf)
        if not verdicts:
            return Verdict.ALLOW
        return max(verdicts, key=lambda v: self._PRECEDENCE[v])

    def evaluate(self, text: str) -> tuple[Verdict, list[RuleResult]]:
        results = [r.evaluate(text) for r in self.rules]
        clf = self.classifier(text) if self.classifier else None
        return self._combine(results, clf), results

    pre = evaluate
    post = evaluate


# ───────────────────────────── ReliabilityLayer ────────────────────────────
class CircuitOpenError(RuntimeError):
    pass


class ReliabilityLayer:
    """
    Semaphore-bounded concurrency + per-call timeout + circuit breaker. When the
    system is saturated or the breaker is open, callers get a controlled failure
    or a safe default -- never an unbounded hang or a crash.
    """

    def __init__(self, max_concurrent: int = 10, timeout_s: float = 30.0,
                 breaker_threshold: int = 5, breaker_cooldown_s: float = 30.0):
        self._sem = asyncio.Semaphore(max_concurrent)
        self.timeout_s = timeout_s
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown_s = breaker_cooldown_s
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self.max_concurrent = max_concurrent

    def _breaker_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.time() - self._opened_at >= self.breaker_cooldown_s:
            # half-open: allow a trial call
            self._opened_at = None
            self._consecutive_failures = 0
            return False
        return True

    async def guard(self, coro_factory: Callable[[], Awaitable]):
        if self._breaker_open():
            raise CircuitOpenError("circuit breaker is open")
        async with self._sem:
            try:
                result = await asyncio.wait_for(coro_factory(), timeout=self.timeout_s)
                self._consecutive_failures = 0
                return result
            except Exception:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.breaker_threshold:
                    self._opened_at = time.time()
                raise


# ──────────────────────────────── HITLLayer ────────────────────────────────
class HITLLayer:
    """
    Human-in-the-loop gateway. For actions classified as consequential, the agent
    proposes and WAITS. The hard invariant: on timeout it returns IDLE and the
    action is NOT taken. Silence is never consent.

    `approver` is an async callable that returns True/False/None (None = no answer).
    In production this is a webhook / Slack / PagerDuty integration. In the demo
    it is supplied directly.
    """

    def __init__(self, require_approval_for: list[str] | None = None,
                 timeout_s: float = 300.0,
                 approver: Optional[Callable[[str, dict], Awaitable[Optional[bool]]]] = None):
        self.require_approval_for = set(require_approval_for or [])
        self.timeout_s = timeout_s
        self.approver = approver

    def is_consequential(self, action: str) -> bool:
        return action in self.require_approval_for

    async def gate(self, action: str, context: dict) -> HITLStatus:
        if not self.is_consequential(action):
            return HITLStatus.AUTO
        if self.approver is None:
            # no approver wired -> safest default is to do nothing
            return HITLStatus.IDLE
        try:
            answer = await asyncio.wait_for(self.approver(action, context), timeout=self.timeout_s)
        except asyncio.TimeoutError:
            return HITLStatus.IDLE
        if answer is True:
            return HITLStatus.APPROVED
        if answer is False:
            return HITLStatus.DENIED
        return HITLStatus.IDLE
