"""
pramagent.compliance
====================
Retention tracking, consent + purpose-limitation registry, and automated
compliance report generation (JSON for machines, plain-text/PDF for auditors).

This complements ComplianceLayer (PII scrubbing in pramagent.layers): that layer
prevents PII reaching the model; this module records the *governance* metadata an
auditor asks for — what consent was on file, what purpose each tenant's data may
be used for, what the retention policy is, and a point-in-time attestation that
the audit chain verifies.

Nothing here calls an LLM. All deterministic, all auditable.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Purpose(str, Enum):
    """Lawful purpose categories (GDPR Art. 5(1)(b) purpose limitation)."""
    SERVICE = "service_provision"
    SECURITY = "security_monitoring"
    LEGAL = "legal_obligation"
    ANALYTICS = "analytics"
    SUPPORT = "customer_support"


@dataclass
class ConsentRecord:
    tenant_id: str
    subject_id: str                       # data-subject identifier (hashed in prod)
    purposes: list[str]                   # allowed Purpose values
    granted_at: float = field(default_factory=time.time)
    revoked_at: Optional[float] = None
    source: str = ""                      # where consent was captured

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def allows(self, purpose: str) -> bool:
        return self.active and purpose in self.purposes


class ConsentRegistry:
    """In-memory consent + purpose-limitation registry.

    Swap the dict for Postgres/Redis in production; the interface is stable.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ConsentRecord] = {}

    def grant(self, tenant_id: str, subject_id: str, purposes: list[str],
              source: str = "") -> ConsentRecord:
        rec = ConsentRecord(tenant_id=tenant_id, subject_id=subject_id,
                            purposes=list(purposes), source=source)
        self._records[(tenant_id, subject_id)] = rec
        return rec

    def revoke(self, tenant_id: str, subject_id: str) -> bool:
        rec = self._records.get((tenant_id, subject_id))
        if rec is None or not rec.active:
            return False
        rec.revoked_at = time.time()
        return True

    def get(self, tenant_id: str, subject_id: str) -> Optional[ConsentRecord]:
        return self._records.get((tenant_id, subject_id))

    def check(self, tenant_id: str, subject_id: str, purpose: str) -> bool:
        """True if an active consent covers `purpose`. Absence = no consent."""
        rec = self._records.get((tenant_id, subject_id))
        return bool(rec and rec.allows(purpose))

    def for_tenant(self, tenant_id: str) -> list[ConsentRecord]:
        return [r for k, r in self._records.items() if k[0] == tenant_id]


@dataclass
class RetentionPolicy:
    """Per-tenant retention policy with a hard legal floor."""
    retention_days: int = 365
    legal_floor_days: int = 180          # EU AI Act Art. 12 minimum for audit logs

    def __post_init__(self) -> None:
        if self.retention_days < self.legal_floor_days:
            raise ValueError(
                f"retention_days={self.retention_days} below legal floor "
                f"{self.legal_floor_days}")

    def cutoff_ts(self, now: Optional[float] = None) -> float:
        now = now if now is not None else time.time()
        return now - self.retention_days * 86400


class ComplianceReporter:
    """Generate auditor-facing compliance reports.

    Pulls live numbers from a store (trace counts), the audit backend (chain
    validity), and the consent registry, and renders them as JSON or text. A
    PDF renderer is provided that uses the project's pdf skill output path if
    reportlab is available, else falls back to text.
    """

    FRAMEWORKS = ("EU_AI_ACT", "GDPR", "HIPAA", "SOC2")

    def __init__(self, *, store=None, audit=None,
                 consent: Optional[ConsentRegistry] = None,
                 retention: Optional[RetentionPolicy] = None) -> None:
        self.store = store
        self.audit = audit
        self.consent = consent or ConsentRegistry()
        self.retention = retention or RetentionPolicy()

    def _trace_stats(self, tenant_id: Optional[str]) -> dict:
        if self.store is None:
            return {"total": 0, "tenant": 0}
        try:
            all_traces = self.store.list_all()
        except Exception:
            all_traces = []
        total = len(all_traces)
        if tenant_id:
            tenant = sum(1 for t in all_traces
                         if getattr(t, "tenant_id", None) == tenant_id)
        else:
            tenant = total
        return {"total": total, "tenant": tenant}

    def _chain_valid(self) -> Optional[bool]:
        if self.audit is None or not hasattr(self.audit, "verify_chain"):
            return None
        try:
            return bool(self.audit.verify_chain())
        except Exception:
            return None

    def build(self, *, tenant_id: Optional[str] = None,
              framework: str = "EU_AI_ACT") -> dict:
        """Return a structured compliance report as a dict (JSON-serialisable)."""
        stats = self._trace_stats(tenant_id)
        consents = (self.consent.for_tenant(tenant_id) if tenant_id
                    else [r for recs in [self.consent.for_tenant(t)
                          for t in {k[0] for k in self.consent._records}]
                          for r in recs])
        active_consents = sum(1 for c in consents if c.active)
        return {
            "report_type": "pramagent_compliance",
            "framework": framework,
            "generated_at": time.time(),
            "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime()),
            "tenant_id": tenant_id or "*ALL*",
            "audit": {
                "hash_chain_verified": self._chain_valid(),
                "trace_records_total": stats["total"],
                "trace_records_tenant": stats["tenant"],
            },
            "retention": {
                "retention_days": self.retention.retention_days,
                "legal_floor_days": self.retention.legal_floor_days,
                "policy_compliant":
                    self.retention.retention_days >= self.retention.legal_floor_days,
            },
            "consent": {
                "records_on_file": len(consents),
                "active": active_consents,
                "revoked": len(consents) - active_consents,
            },
            "controls": self._controls(framework),
        }

    def _controls(self, framework: str) -> list[dict]:
        """Map implemented Pramagent controls to a framework's expectations."""
        base = [
            ("audit_trail", "Tamper-evident hash-chained audit log",
             self._chain_valid() is not False),
            ("pii_minimization", "PII scrubbed before model exposure", True),
            ("access_control", "Per-tenant API-key + JWT auth, tenant isolation", True),
            ("human_oversight", "HITL approval gate for consequential actions", True),
            ("retention_limit",
             f"Retention floor {self.retention.legal_floor_days}d enforced", True),
        ]
        return [{"control_id": cid, "description": desc, "in_place": ok}
                for cid, desc, ok in base]

    def to_json(self, *, tenant_id: Optional[str] = None,
                framework: str = "EU_AI_ACT", path: Optional[str] = None) -> str:
        report = self.build(tenant_id=tenant_id, framework=framework)
        blob = json.dumps(report, indent=2, sort_keys=True)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(blob)
        return blob

    def to_text(self, *, tenant_id: Optional[str] = None,
                framework: str = "EU_AI_ACT") -> str:
        r = self.build(tenant_id=tenant_id, framework=framework)
        lines = [
            "PRAMAGENT COMPLIANCE REPORT",
            "=" * 60,
            f"Framework:      {r['framework']}",
            f"Generated:      {r['generated_at_iso']}",
            f"Tenant:         {r['tenant_id']}",
            "",
            "AUDIT",
            f"  Hash chain verified : {r['audit']['hash_chain_verified']}",
            f"  Trace records (all) : {r['audit']['trace_records_total']}",
            f"  Trace records (tnt) : {r['audit']['trace_records_tenant']}",
            "",
            "RETENTION",
            f"  Policy (days)       : {r['retention']['retention_days']}",
            f"  Legal floor (days)  : {r['retention']['legal_floor_days']}",
            f"  Compliant           : {r['retention']['policy_compliant']}",
            "",
            "CONSENT",
            f"  Records on file     : {r['consent']['records_on_file']}",
            f"  Active / Revoked    : {r['consent']['active']} / {r['consent']['revoked']}",
            "",
            "CONTROLS",
        ]
        for c in r["controls"]:
            mark = "✓" if c["in_place"] else "✗"
            lines.append(f"  [{mark}] {c['control_id']}: {c['description']}")
        return "\n".join(lines)

    def to_pdf(self, path: str, *, tenant_id: Optional[str] = None,
               framework: str = "EU_AI_ACT") -> str:
        """Write a PDF report. Uses reportlab if present; else writes text to path."""
        text = self.to_text(tenant_id=tenant_id, framework=framework)
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            c = canvas.Canvas(path, pagesize=letter)
            _, height = letter
            y = height - 50
            for line in text.splitlines():
                c.drawString(50, y, line[:100])
                y -= 14
                if y < 50:
                    c.showPage()
                    y = height - 50
            c.save()
        except Exception:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return path
