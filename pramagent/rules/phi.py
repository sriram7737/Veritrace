"""
pramagent.rules.phi
===================
HIPAA Protected Health Information (PHI) patterns beyond what
ComplianceLayer (in pramagent.layers) already covers.

ComplianceLayer catches: email, SSN, credit card, phone, account, IBAN,
routing number (in context), date of birth (in context).

This corpus adds the healthcare-specific identifiers in HIPAA Safe Harbor
§164.514(b)(2):
  - Medical record number (MRN)
  - Health plan / insurance member ID
  - Provider NPI (National Provider Identifier)
  - ICD-10 diagnosis codes
  - CPT procedure codes
  - DEA prescriber number
  - Prescription / Rx number

Patterns are REDACT (not BLOCK) by default — the goal is to scrub PHI from
prompts that reach the model, not to refuse the whole call. SafetyLayer's
precedence (BLOCK > ESCALATE > REDACT > ALLOW) means an explicit BLOCK rule
elsewhere still wins.
"""
from __future__ import annotations

from ..layers import Rule
from ..types import Verdict


_PATTERNS: list[tuple[str, str, str]] = [
    # Medical record number — appears as "MRN: 12345678" or "MRN# 12345"
    ("phi_mrn",
     r"\bMRN\s*[#:.]?\s*\d{5,12}\b",
     "HIPAA Safe Harbor (B): medical record number"),

    # NPI — 10-digit National Provider Identifier
    ("phi_npi",
     r"\bNPI\s*[#:.]?\s*\d{10}\b",
     "HIPAA Safe Harbor (E): provider NPI"),

    # Health plan / member ID — usually labelled
    ("phi_member_id",
     r"\b(?:member|policy|plan|subscriber)\s*(?:id|#|number)\s*[#:.]?\s*[A-Z]{0,3}\d{6,12}\b",
     "HIPAA Safe Harbor (G): health plan beneficiary number"),

    # ICD-10 diagnosis code — letter + digit + digit, optional .digit(s)
    ("phi_icd10",
     r"\b(?:ICD[- ]?10[- ]?(?:CM|PCS)?\s*[:#]?\s*)?[A-TV-Z]\d{2}(?:\.[0-9A-TV-Z]{1,4})?\b(?=\s|$|[,;.])",
     "HIPAA: ICD-10 diagnosis code"),

    # CPT procedure code — 5 digits, labelled
    ("phi_cpt",
     r"\bCPT\s*[#:.]?\s*\d{5}\b",
     "HIPAA: CPT procedure code"),

    # DEA prescriber registration number — 2 letters + 7 digits
    ("phi_dea",
     r"\bDEA\s*[#:.]?\s*[A-Z]{2}\d{7}\b",
     "HIPAA: DEA prescriber number"),

    # Rx / prescription number — labelled
    ("phi_rx_number",
     r"\b(?:Rx|prescription)\s*(?:#|no\.?|number)?\s*[:.]?\s*\d{6,12}\b",
     "HIPAA: prescription number"),

    # Health insurance group number
    ("phi_group_number",
     r"\bgroup\s*(?:#|no\.?|number)\s*[:.]?\s*[A-Z0-9]{4,12}\b",
     "HIPAA: insurance group number"),

    # Device identifier (HIPAA Safe Harbor (R))
    ("phi_device_id",
     r"\b(?:device|implant|serial)\s*(?:id|#|number)\s*[:.]?\s*[A-Z0-9-]{6,20}\b",
     "HIPAA Safe Harbor (R): device identifier"),

    # Biometric identifier markers (fingerprint, voiceprint hashes)
    ("phi_biometric_marker",
     r"\b(?:fingerprint|voiceprint|iris|retina)\s+(?:hash|template|id)\s*[:.]?\s*[A-F0-9]{16,}\b",
     "HIPAA Safe Harbor (Q): biometric identifier"),

    # Health-claim / account combos
    ("phi_claim_number",
     r"\bclaim\s*(?:#|no\.?|number)\s*[:.]?\s*[A-Z0-9-]{6,20}\b",
     "HIPAA: health claim number"),
]


PHI_PATTERNS: list[Rule] = [
    Rule(rule_id=rid, action=Verdict.REDACT, pattern=pat, detail=detail)
    for rid, pat, detail in _PATTERNS
]

__all__ = ["PHI_PATTERNS"]
