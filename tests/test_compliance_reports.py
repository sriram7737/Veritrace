"""Tests for consent registry, retention policy, and compliance reports."""
import json
import os
import tempfile

import pytest

from veritrace.compliance import (ComplianceReporter, ConsentRegistry,
                                   Purpose, RetentionPolicy)
from veritrace.store import MemoryStore
from veritrace.audit import HashChainBackend
from veritrace.types import TraceEvent


# ── ConsentRegistry ────────────────────────────────────────────────────────
def test_grant_and_check_consent():
    reg = ConsentRegistry()
    reg.grant("acme", "subj1", [Purpose.SERVICE, Purpose.ANALYTICS])
    assert reg.check("acme", "subj1", Purpose.SERVICE)
    assert reg.check("acme", "subj1", Purpose.ANALYTICS)
    assert not reg.check("acme", "subj1", Purpose.SECURITY)


def test_consent_absence_is_no_consent():
    reg = ConsentRegistry()
    assert not reg.check("acme", "nobody", Purpose.SERVICE)


def test_revoke_consent():
    reg = ConsentRegistry()
    reg.grant("acme", "subj1", [Purpose.SERVICE])
    assert reg.check("acme", "subj1", Purpose.SERVICE)
    assert reg.revoke("acme", "subj1") is True
    assert not reg.check("acme", "subj1", Purpose.SERVICE)
    # double revoke is a no-op
    assert reg.revoke("acme", "subj1") is False


def test_purpose_limitation_isolates_tenants():
    reg = ConsentRegistry()
    reg.grant("acme", "s", [Purpose.SERVICE])
    # different tenant, same subject id, no consent
    assert not reg.check("other", "s", Purpose.SERVICE)
    assert len(reg.for_tenant("acme")) == 1
    assert len(reg.for_tenant("other")) == 0


# ── RetentionPolicy ────────────────────────────────────────────────────────
def test_retention_below_floor_rejected():
    with pytest.raises(ValueError):
        RetentionPolicy(retention_days=30)


def test_retention_cutoff_is_in_past():
    import time
    pol = RetentionPolicy(retention_days=200)
    assert pol.cutoff_ts(now=1000.0 * 86400) < 1000.0 * 86400


# ── ComplianceReporter ─────────────────────────────────────────────────────
def _armed_store():
    store = MemoryStore()
    audit = HashChainBackend()
    for i in range(3):
        tr = TraceEvent(tenant_id="acme", session_id="s", input_text=f"x{i}")
        payload = tr.to_dict()
        for k in ("this_hash", "anchor_tx_id", "prev_hash"):
            payload.pop(k, None)
        tr.prev_hash = audit.head
        tr.this_hash, tr.anchor_tx_id = audit.append(payload, tr.prev_hash)
        store.save(tr)
    return store, audit


def test_report_build_has_all_sections():
    store, audit = _armed_store()
    rep = ComplianceReporter(store=store, audit=audit)
    r = rep.build(tenant_id="acme")
    assert r["audit"]["hash_chain_verified"] is True
    assert r["audit"]["trace_records_tenant"] == 3
    assert r["retention"]["policy_compliant"] is True
    assert any(c["control_id"] == "audit_trail" for c in r["controls"])


def test_report_json_and_text():
    store, audit = _armed_store()
    rep = ComplianceReporter(store=store, audit=audit)
    blob = rep.to_json(tenant_id="acme")
    parsed = json.loads(blob)
    assert parsed["framework"] == "EU_AI_ACT"
    text = rep.to_text(tenant_id="acme")
    assert "VERITRACE COMPLIANCE REPORT" in text
    assert "HASH CHAIN" in text.upper()


def test_report_pdf_writes_file():
    store, audit = _armed_store()
    rep = ComplianceReporter(store=store, audit=audit)
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        out = rep.to_pdf(path, tenant_id="acme")
        assert os.path.exists(out)
        assert os.path.getsize(out) > 0
    finally:
        os.unlink(path)


def test_report_consent_counts():
    store, audit = _armed_store()
    consent = ConsentRegistry()
    consent.grant("acme", "s1", [Purpose.SERVICE])
    consent.grant("acme", "s2", [Purpose.SERVICE])
    consent.revoke("acme", "s2")
    rep = ComplianceReporter(store=store, audit=audit, consent=consent)
    r = rep.build(tenant_id="acme")
    assert r["consent"]["records_on_file"] == 2
    assert r["consent"]["active"] == 1
    assert r["consent"]["revoked"] == 1
