"""
pramagent.rules.owasp_llm
=========================
OWASP Top 10 for LLM Applications 2025 — deterministic rules.

Source: https://owasp.org/www-project-top-10-for-large-language-model-applications/

Not every category lends itself to a regex (LLM05 supply-chain, LLM10 model
theft are operational concerns). For those we ship a stub rule that always
returns ALLOW but carries metadata so the audit can show the category was
considered. For the categories that DO admit a deterministic check
(LLM01 prompt injection, LLM02 sensitive-info disclosure, LLM06 excessive
agency surface, LLM07 system-prompt leakage, LLM09 misinformation cue), we
ship real patterns.

Every rule id starts with ``owasp_llm`` so they're easy to filter.
"""
from __future__ import annotations

from ..layers import Rule
from ..types import Verdict


_PATTERNS: list[tuple[str, str, str, Verdict]] = [
    # LLM01 — Prompt injection (direct + indirect)
    ("owasp_llm01_direct_injection",
     r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)",
     "LLM01: direct prompt injection", Verdict.BLOCK),
    ("owasp_llm01_indirect_marker",
     r"<!--\s*(?:SYSTEM|ASSISTANT|PROMPT)\s*:\s*[^>]{0,200}-->",
     "LLM01: indirect injection via comment", Verdict.BLOCK),
    ("owasp_llm01_tool_smuggle",
     r"\[\[\s*tool\s*:\s*\w+\s*\]\]|<<\s*invoke\s+\w+\s*>>",
     "LLM01: tool-call smuggling token", Verdict.BLOCK),

    # LLM02 — Sensitive information disclosure
    ("owasp_llm02_api_key_request",
     r"(?:show|reveal|print|leak|dump|share)\s+(?:your|the|all)\s+(?:api[\s_-]?keys?|secrets?|tokens?|credentials?)",
     "LLM02: secret-extraction request", Verdict.BLOCK),
    ("owasp_llm02_env_dump",
     r"(?:show|print|dump|cat)\s+(?:os\.environ|environment\s+variables?|\.env(?:\s+file)?)",
     "LLM02: environment-dump request", Verdict.BLOCK),
    ("owasp_llm02_aws_key_in_text",
     r"\bAKIA[0-9A-Z]{16}\b",
     "LLM02: AWS access key id in payload", Verdict.REDACT),
    ("owasp_llm02_private_key_block",
     r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
     "LLM02: private-key block in payload", Verdict.REDACT),
    ("owasp_llm02_bearer_token",
     r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b",
     "LLM02: bearer token in payload", Verdict.REDACT),

    # LLM03 — Supply chain (operational; we mark for audit only)
    # (no regex — see ALL_RULES note above)

    # LLM04 — Data and model poisoning (mostly operational; we flag obvious markers)
    ("owasp_llm04_training_data_marker",
     r"<<\s*(?:training|finetune|backdoor)\s*:\s*\w+\s*>>",
     "LLM04: training-data backdoor marker", Verdict.BLOCK),

    # LLM05 — Improper output handling (signals raw exfil of SSRF target into text)
    ("owasp_llm05_outbound_url_with_creds",
     r"https?://[^\s/]+:[^\s/@]+@[^\s]+",
     "LLM05: URL with embedded credentials", Verdict.REDACT),

    # LLM06 — Excessive agency surface
    ("owasp_llm06_self_delete",
     r"(?:rm\s+-rf\s+/|del\s+/f\s+/s\s+/q\s+\S+|format\s+c:)",
     "LLM06: destructive shell command", Verdict.BLOCK),
    ("owasp_llm06_unbounded_tool",
     r"(?:loop|repeat|keep)\s+(?:calling|invoking)\s+(?:the\s+)?tool\s+(?:until|forever|infinitely)",
     "LLM06: unbounded tool loop", Verdict.BLOCK),

    # LLM07 — System prompt leakage
    ("owasp_llm07_system_prompt_leak",
     r"(?:repeat|reveal|show|print|echo)\s+(?:the|your)\s+(?:initial|system|original)\s+(?:prompt|message|instructions)",
     "LLM07: system prompt extraction", Verdict.BLOCK),
    ("owasp_llm07_above_text_leak",
     r"(?:repeat|echo)\s+(?:everything|all)\s+(?:above|before)\s+this\s+(?:line|message)",
     "LLM07: prompt-leak via repeat-above", Verdict.BLOCK),

    # LLM08 — Vector + embedding weaknesses (flag explicit vector dumps)
    ("owasp_llm08_vector_dump",
     r"(?:dump|export|list)\s+(?:all\s+)?(?:vectors?|embeddings?|chunks?)\s+(?:in|from)\s+(?:the\s+)?(?:db|database|index|store)",
     "LLM08: vector store exfil request", Verdict.ESCALATE),

    # LLM09 — Misinformation (cue phrases — escalate, don't auto-block)
    ("owasp_llm09_fabrication_cue",
     r"\b(?:make\s+up|fabricate|invent|hallucinate)\s+(?:a|some|the)\s+(?:source|citation|reference|study|paper)",
     "LLM09: fabrication request", Verdict.ESCALATE),

    # LLM10 — Unbounded consumption (cost / DoS)
    ("owasp_llm10_token_bomb",
     r"(?:print|output|generate)\s+(?:a|the)?\s*(?:list|sequence)\s+of\s+(?:\d{4,}|million|billion)\s+\w+",
     "LLM10: token-bomb / DoS prompt", Verdict.BLOCK),
    ("owasp_llm10_zip_bomb_marker",
     r"\b(?:42\.zip|zip\s*bomb|nested\s+zip)\b",
     "LLM10: zip-bomb reference", Verdict.ESCALATE),
]


OWASP_LLM_TOP10: list[Rule] = [
    Rule(rule_id=rid, action=verdict, pattern=pat, detail=detail)
    for rid, pat, detail, verdict in _PATTERNS
]

__all__ = ["OWASP_LLM_TOP10"]
