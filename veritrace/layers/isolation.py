"""
veritrace.layers.isolation
==========================
Real isolation primitives. Three defenses:

  1. Tenant-scoped memory backed by an AbstractBackend (in-process default,
     Redis for multi-worker deployments). Writing to tenant A does not bleed
     into tenant B; cross-scope reads raise IsolationViolation.

  2. Injection heuristics. Scans inbound prompts for common instruction-override
     and exfiltration patterns. These are heuristics, not a complete defense.
     An ML classifier hook is provided for layering stronger detection.

  3. Hard size limits. Input and output bytes are capped per call to prevent
     trivial DoS and bound LLM costs. Configurable per deployment.

What this layer does NOT claim to do
-------------------------------------
It does not defend against a determined attacker with novel injection prompts.
Real defense requires fine-tuned classifiers, provenance tracking on tool
outputs, and runtime constraints on the model action space.
"""
from __future__ import annotations

import re
from typing import Callable, Optional


class IsolationViolation(Exception):
    """Raised when a request crosses tenant or session boundaries."""


class InputTooLarge(Exception):
    """Raised when an input exceeds the configured byte limit."""


class InjectionSuspected(Exception):
    """Raised when injection heuristics fire on the input. Heuristic, not proof."""


_INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("instruction_override",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
                re.IGNORECASE),
     "classic prompt-injection override"),
    ("role_hijack",
     re.compile(r"(?m)^\s*(system|assistant|developer)\s*[:>]", re.IGNORECASE),
     "attempt to inject a fake role/turn header"),
    ("disregard_safety",
     re.compile(r"(disregard|bypass|ignore|override)\s+(your\s+)?(safety|guidelines|rules|policies)",
                re.IGNORECASE),
     "explicit safety bypass request"),
    ("data_exfiltration",
     re.compile(r"(dump|print|reveal|show|leak|exfiltrate)\s+(all\s+|the\s+)?(memory|secrets?|keys?|tokens?|env(ironment)?|database|users?)",
                re.IGNORECASE),
     "request to reveal internal state or secrets"),
    ("pretend_you_are",
     re.compile(
         r"(pretend|act|behave|roleplay)\s+"
         r"(?:(?:as|like)\s+(?:if\s+)?)?"
         r"(?:you\s+are\s+|you\'re\s+)?"
         r"(?:an?\s+)?"
         r"(unrestricted|uncensored|jailbroken|dan\b)",
         re.IGNORECASE),
     "jailbreak persona request"),
    ("encoded_payload",
     re.compile(r"\b(decode|execute|run)\s+(this\s+)?(base64|hex|rot13|payload)",
                re.IGNORECASE),
     "request to decode/run obfuscated payload"),
    ("delimiter_break",
     re.compile(r"(```\s*end\s+of\s+prompt|<\|im_end\|>|<\|endoftext\|>|---\s*new\s+prompt)",
                re.IGNORECASE),
     "attempt to inject a chat-template delimiter"),
]


class IsolationLayer:
    """
    Tenant-scoped memory + injection heuristics + size limits.

    Configuration
    -------------
    max_input_bytes   : cap on input prompt size (default 64 KiB)
    max_output_bytes  : cap on output text size (default 64 KiB)
    block_on_injection: True (default) raises InjectionSuspected on a hit;
                        False just records the hits in trace metadata.
    classifier        : optional callable(text) -> bool; True = malicious.
    backend           : AbstractBackend for tenant memory. Defaults to
                        InProcessBackend. Pass RedisBackend for multi-worker.
    memory_ttl_s      : TTL for memory entries in seconds (default 3600).
    """

    def __init__(
        self,
        max_input_bytes: int = 64 * 1024,
        max_output_bytes: int = 64 * 1024,
        block_on_injection: bool = True,
        classifier: Optional[Callable[[str], bool]] = None,
        backend=None,
        memory_ttl_s: int = 3600,
    ) -> None:
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes
        self.block_on_injection = block_on_injection
        self.classifier = classifier
        self.memory_ttl_s = memory_ttl_s
        if backend is None:
            from ..backends import InProcessBackend
            backend = InProcessBackend()
        self._backend = backend

    @staticmethod
    def _scope_key(tenant_id: str, session_id: str) -> str:
        return f"{tenant_id}:{session_id}"

    def memory_for(self, tenant_id: str, session_id: str) -> list[str]:
        """Return a copy of this scope\'s memory."""
        return self._backend.memory_get(self._scope_key(tenant_id, session_id))

    def memory_append(self, tenant_id: str, session_id: str, item: str) -> None:
        """Append an item to scope memory (safe for multi-worker)."""
        self._backend.memory_append(self._scope_key(tenant_id, session_id), item)

    def assert_scope(self, tenant_id: str, session_id: str,
                     expected_tenant: str, expected_session: str) -> None:
        if tenant_id != expected_tenant or session_id != expected_session:
            raise IsolationViolation(
                f"scope mismatch: got ({tenant_id},{session_id}) "
                f"expected ({expected_tenant},{expected_session})"
            )

    def clear_scope(self, tenant_id: str, session_id: str) -> None:
        self._backend.memory_clear(self._scope_key(tenant_id, session_id))

    def check_input_size(self, text: str) -> None:
        size = len(text.encode("utf-8"))
        if size > self.max_input_bytes:
            raise InputTooLarge(
                f"input is {size} bytes; limit is {self.max_input_bytes}"
            )

    def truncate_output(self, text: str) -> tuple[str, bool]:
        b = text.encode("utf-8")
        if len(b) <= self.max_output_bytes:
            return text, False
        return b[: self.max_output_bytes].decode("utf-8", errors="ignore"), True

    def scan_for_injection(self, text: str) -> list[dict]:
        """Return hits for every heuristic that fires. Empty = no match (not safe)."""
        hits = []
        for pid, rx, detail in _INJECTION_PATTERNS:
            if rx.search(text):
                hits.append({"pattern_id": pid, "detail": detail})
        return hits

    async def evaluate_input(self, text: str, *, tenant_id: str,
                             session_id: str) -> dict:
        """Run all checks on an inbound prompt. Raises on hard violations."""
        self.check_input_size(text)

        hits = self.scan_for_injection(text)
        classifier_verdict: Optional[bool] = None
        if self.classifier is not None:
            classifier_verdict = bool(self.classifier(text))

        suspected = bool(hits) or (classifier_verdict is True)
        if suspected and self.block_on_injection:
            reasons = [h["pattern_id"] for h in hits]
            if classifier_verdict:
                reasons.append("classifier")
            raise InjectionSuspected(",".join(reasons) or "classifier")

        return {
            "scope": f"{tenant_id}:{session_id}",
            "injection_hits": hits,
            "classifier_flagged": classifier_verdict,
            "input_bytes": len(text.encode("utf-8")),
        }
