"""Regression tests for context-guarded PII scrubbing."""
from veritrace.layers import ComplianceLayer


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
