import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from pramagent import Pramagent  # noqa: E402
from pramagent.api.app import create_app  # noqa: E402
from pramagent.hitl.slack import (SlackApprovalRegistry, SlackHITLApprover,  # noqa: E402
                                  SlackApprovalError, verify_slack_signature)
from pramagent.layers import HITLLayer  # noqa: E402


class FakeSlackClient:
    def __init__(self):
        self.messages = []

    async def post_approval(self, **kwargs):
        self.messages.append(kwargs)


class FailingSlackClient:
    async def post_approval(self, **kwargs):
        raise SlackApprovalError("Slack rejected approval message: invalid_auth")


def _slack_headers(secret: str, body: bytes):
    ts = str(int(time.time()))
    base = b"v0:" + ts.encode("ascii") + b":" + body
    sig = "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": sig,
        "Content-Type": "application/x-www-form-urlencoded",
    }


def test_verify_slack_signature_accepts_valid_request():
    secret = "secret"
    ts = str(int(time.time()))
    body = b"payload={}"
    base = b"v0:" + ts.encode("ascii") + b":" + body
    sig = "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()

    assert verify_slack_signature(
        signing_secret=secret, timestamp=ts, body=body, signature=sig
    )


def test_verify_slack_signature_rejects_bad_signature():
    assert not verify_slack_signature(
        signing_secret="secret",
        timestamp=str(int(time.time())),
        body=b"payload={}",
        signature="v0=bad",
    )


def test_slack_callback_records_approval():
    secret = "test-secret"
    registry = SlackApprovalRegistry()
    fake_slack = FakeSlackClient()
    approver = SlackHITLApprover(
        bot_token="xoxb-test",
        channel_id="C123",
        signing_secret=secret,
        public_url="https://example.test",
        registry=registry,
        client=fake_slack,
    )
    armor = Pramagent(
        hitl=HITLLayer(
            require_approval_for=["wire_transfer"],
            timeout_s=1.0,
            approver=approver,
        )
    )
    client = TestClient(create_app(armor=armor))

    request = registry.create("wire_transfer", {"tenant": "bank"})
    payload = {
        "actions": [{
            "action_id": "pramagent_approve",
            "value": request.request_id,
        }]
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")

    response = client.post(
        "/v1/hitl/slack/action",
        data=body,
        headers=_slack_headers(secret, body),
    )

    assert response.status_code == 200
    assert registry._pending[request.request_id].decision is True


def test_slack_callback_rejects_invalid_signature():
    approver = SlackHITLApprover(
        bot_token="xoxb-test",
        channel_id="C123",
        signing_secret="test-secret",
        public_url="https://example.test",
        client=FakeSlackClient(),
    )
    armor = Pramagent(hitl=HITLLayer(require_approval_for=["wire_transfer"], approver=approver))
    client = TestClient(create_app(armor=armor))

    response = client.post(
        "/v1/hitl/slack/action",
        data=urlencode({"payload": "{}"}),
        headers={
            "X-Slack-Request-Timestamp": str(int(time.time())),
            "X-Slack-Signature": "v0=bad",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_slack_post_failure_returns_no_decision():
    approver = SlackHITLApprover(
        bot_token="xoxb-test",
        channel_id="C123",
        signing_secret="test-secret",
        public_url="https://example.test",
        client=FailingSlackClient(),
    )

    assert await approver("wire_transfer", {"tenant": "bank"}) is None
