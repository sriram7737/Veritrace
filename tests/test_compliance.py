"""Regression tests for context-guarded PII scrubbing."""
from pramagent.layers import ComplianceLayer


def test_bare_nine_digits_not_redacted_without_context():
    c = ComplianceLayer()
    out, red = c.scrub("Your order 123456789 shipped today.")
    assert "routing_number" not in red
    assert "123456789" in out


def test_iso_date_not_redacted_without_context():
    c = ComplianceLayer()
    out, red = c.scrub("The incident occurred on 2025-11-03.")
    assert "dob" not in red
    assert "2025-11-03" in out


def test_routing_number_redacted_with_context():
    c = ComplianceLayer()
    out, red = c.scrub("Wire to routing number 021000021 today.")
    assert "routing_number" in red
    assert "021000021" not in out


def test_dob_redacted_with_context():
    c = ComplianceLayer()
    out, red = c.scrub("Patient DOB: 1985-03-12.")
    assert "dob" in red
    assert "1985-03-12" not in out


def test_high_precision_patterns_always_redact():
    c = ComplianceLayer()
    out, red = c.scrub("email jane@x.com SSN 123-45-6789 IBAN DE89370400440532013000")
    assert {"email", "ssn", "iban"}.issubset(set(red))
    assert "jane@x.com" not in out and "123-45-6789" not in out


def test_multiple_emails_all_redacted():
    """The bounded email handler must catch every email, not just the first."""
    c = ComplianceLayer()
    out, red = c.scrub("Contact jane@example.com or bob.smith@corp.example.org today.")
    assert red.count("email") == 2
    assert "jane@example.com" not in out
    assert "bob.smith@corp.example.org" not in out
    assert "Contact" in out and "today." in out


# ── SEC-2026-06-11-01: regex CPU DoS regressions ───────────────────────────

def test_scrub_long_no_match_completes_fast():
    """Long alphabetic input previously triggered superlinear backtracking in
    the email pattern (16 KiB ≈ 1.3 s; 256 KiB never finished). The bounded
    two-phase handler must keep scrub linear."""
    import time
    layer = ComplianceLayer()
    for size in [1024, 16384, 65536, 262144]:
        t0 = time.perf_counter()
        result = layer.scrub("x" * size)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.5, f"scrub({size}) took {elapsed:.2f}s > 0.5s budget"
        assert "[REDACTED" not in result[0]  # no false positives


def test_prompt_cap_runs_before_scrubbing():
    """The pipeline must reject oversized input BEFORE ComplianceLayer.scrub()
    sees it — the isolation byte cap is the first gate."""
    import asyncio
    from unittest.mock import patch

    from pramagent import Pramagent

    armor = Pramagent()
    with patch.object(armor.compliance, "scrub",
                      wraps=armor.compliance.scrub) as mock_scrub:
        try:
            asyncio.run(armor.run("x" * 262145))
        except Exception:
            pass
        # scrub must not have been called with oversized input
        for call in mock_scrub.call_args_list:
            assert len(call.args[0]) <= 262144, \
                "scrub() was called with oversized input"
