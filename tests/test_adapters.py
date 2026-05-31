"""Tests for HITL notification + approval adapters."""
import asyncio
import pytest

from veritrace.hitl.adapters import (CompositeApprover, EmailNotifier,
                                      PagerDutyNotifier, SMTPConfig,
                                      WebhookApprover)


def run(coro):
    return asyncio.run(coro)


# ── WebhookApprover ────────────────────────────────────────────────────────
def test_webhook_notify_only_returns_none(monkeypatch):
    wa = WebhookApprover("https://example.test/notify")
    monkeypatch.setattr(wa, "_post", lambda url, payload: {})
    assert run(wa(action="wire", context={"tenant": "t"})) is None


def test_webhook_polls_decision_approve(monkeypatch):
    wa = WebhookApprover("https://x/notify", decision_url="https://x/decide",
                         poll_interval_s=0.01, timeout_s=1)
    monkeypatch.setattr(wa, "_post", lambda url, payload: {})
    monkeypatch.setattr(wa, "_get", lambda url: {"decision": "approve"})
    assert run(wa(action="wire", context={"request_id": "r1"})) is True


def test_webhook_polls_decision_deny(monkeypatch):
    wa = WebhookApprover("https://x/notify", decision_url="https://x/decide",
                         poll_interval_s=0.01, timeout_s=1)
    monkeypatch.setattr(wa, "_post", lambda url, payload: {})
    monkeypatch.setattr(wa, "_get", lambda url: {"decision": "deny"})
    assert run(wa(action="wire", context={"request_id": "r2"})) is False


def test_webhook_delivery_failure_fails_closed(monkeypatch):
    wa = WebhookApprover("https://x/notify")
    def boom(url, payload):
        raise OSError("network down")
    monkeypatch.setattr(wa, "_post", boom)
    assert run(wa(action="wire", context={})) is None
    assert "network down" in wa.last_error


# ── EmailNotifier ──────────────────────────────────────────────────────────
def test_email_notifier_is_notify_only(monkeypatch):
    sent = {}
    en = EmailNotifier(SMTPConfig(host="smtp.test"), ["sec@co.test"])
    monkeypatch.setattr(en, "_send",
                        lambda subj, body: sent.update(subject=subj, body=body))
    assert run(en(action="delete_data", context={"tenant": "bank"})) is None
    assert "delete_data" in sent["subject"]
    assert "bank" in sent["body"]


# ── PagerDutyNotifier ──────────────────────────────────────────────────────
def test_pagerduty_notifier_triggers_and_returns_none(monkeypatch):
    calls = []
    pd = PagerDutyNotifier("routing-key-123")
    monkeypatch.setattr(pd, "_trigger",
                        lambda action, ctx: calls.append((action, ctx)))
    assert run(pd(action="wire_transfer", context={"amt": 9000})) is None
    assert calls and calls[0][0] == "wire_transfer"


# ── CompositeApprover ──────────────────────────────────────────────────────
def test_composite_alerts_and_delegates_decision():
    notified = []

    async def notifier(action, ctx):
        notified.append(action)
        return None

    async def decider(action, ctx):
        return True

    comp = CompositeApprover(notifiers=[notifier, notifier], decider=decider)
    assert run(comp(action="wire", context={})) is True
    assert notified == ["wire", "wire"]


def test_composite_without_decider_returns_none():
    async def notifier(action, ctx):
        return None
    comp = CompositeApprover(notifiers=[notifier])
    assert run(comp(action="wire", context={})) is None
