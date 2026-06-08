"""
pramagent.rules
===============
Curated, deterministic rule corpora.

Every rule in every corpus is a plain ``Rule`` object — a regex (or callable)
plus an action. There is no model, no classifier, no probability. A human can
read each rule and trace it to its source. That's the contract: an auditor can
open this directory, see exactly what patterns Pramagent enforces, and follow
each one back to a public corpus.

Available corpora
-----------------
- ``JAILBREAK_PATTERNS``  - 50+ jailbreak patterns mined from JailbreakBench,
  HarmBench, Garak, and published red-team write-ups.
- ``OWASP_LLM_TOP10``     - OWASP Top 10 for LLM Applications 2025, mapped to
  detection rules for each category that admits a deterministic check.
- ``INJECTION_CORPUS``    - SQL injection, shell metacharacter, SSRF host
  patterns, path traversal, and server-side template injection.
- ``FICTIONAL_WRAPPER``   - Story / roleplay / hypothetical "wrap a request
  in fiction" bypass patterns.
- ``PHI_PATTERNS``        - HIPAA PHI patterns beyond what ComplianceLayer
  already catches (MRN, NPI, ICD-10, prescription, insurance member ID).
- ``FINANCIAL_PII``       - PCI-DSS-relevant patterns: card brands by BIN,
  CVV in context, routing+account pairs, SWIFT/BIC, crypto wallets.

Use them à la carte::

    from pramagent import Pramagent, SafetyLayer
    from pramagent.rules import JAILBREAK_PATTERNS, OWASP_LLM_TOP10

    armor = Pramagent(
        safety=SafetyLayer(rules=[*JAILBREAK_PATTERNS, *OWASP_LLM_TOP10])
    )

Or import the convenience aggregate::

    from pramagent.rules import ALL_RULES
    armor = Pramagent(safety=SafetyLayer(rules=ALL_RULES))
"""
from __future__ import annotations

from .jailbreak import JAILBREAK_PATTERNS
from .owasp_llm import OWASP_LLM_TOP10
from .injection import INJECTION_CORPUS
from .fictional_wrapper import FICTIONAL_WRAPPER
from .phi import PHI_PATTERNS
from .financial import FINANCIAL_PII

# Convenience: every shipped rule.
ALL_RULES = [
    *JAILBREAK_PATTERNS,
    *OWASP_LLM_TOP10,
    *INJECTION_CORPUS,
    *FICTIONAL_WRAPPER,
    *PHI_PATTERNS,
    *FINANCIAL_PII,
]

__all__ = [
    "JAILBREAK_PATTERNS",
    "OWASP_LLM_TOP10",
    "INJECTION_CORPUS",
    "FICTIONAL_WRAPPER",
    "PHI_PATTERNS",
    "FINANCIAL_PII",
    "ALL_RULES",
]
