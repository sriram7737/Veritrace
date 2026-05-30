"""Slack-backed human approval adapter.

In single-process deployments the default InProcessBackend works fine.
For multi-worker / multi-instance production deployments, pass a RedisBackend
so approval callbacks can land on any worker::

    from veritrace.backends import RedisBackend
    from veritrace.hitl.slack import SlackApprovalRegistry

    backend  = RedisBackend.from_url(os.environ["REDIS_URL"])
    registry = SlackApprovalRegistry(backend=backend)

The registry interface is identical regardless of backend.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


log = logging.getLogger(__name__)


class SlackApprovalError(RuntimeError):
    pass


@dataclass
class PendingApproval:
    request_id: str
    action: str
    context: dict[str, Any]
    created_at: float = field(default_factory=time.time)
    decision: Optional[bool] = None
    # Only used by InProcessBackend path — RedisBackend uses its own wait()
    event: asyncio.Event = field(default_factory=asyncio.Event)


class SlackMessageClient(Protocol):
    async def post_approval(
        self,
        *,
        channel: str,
        request_id: str,
        action: str,
        context: dict[str, Any],
        public_url: str,
    ) -> None:
        ...


class SlackApprovalRegistry:
    """Tracks pending approval requests.

    Backed by an AbstractBackend (in-process by default, Redis for prod).
    """

    def __init__(self, backend: Optional[Any] = None) -> None:
        from ..backends import InProcessBackend
        self._backend = backend or InProcessBackend()
        # in-process fallback for legacy callers that rely on PendingApproval objects
        self._pending: dict[str, PendingApproval] = {}

    def create(self, action: str, context: dict[str, Any]) -> PendingApproval:
        request = PendingApproval(
            request_id=str(uuid.uuid4()),
            action=action,
            context=dict(context),
        )
        self._pending[request.request_id] = request
        # also write to backend so other workers can resolve it
        self._backend.set(
            f"hitl:{request.request_id}",
            {"action": action, "context": context, "created_at": request.created_at},
            ttl_s=3600,
        )
        return request

    async def wait(self, request_id: str, *, timeout_s: float = 300.0) -> Optional[bool]:
        # Try the distributed backend first (works across workers).
        val = await self._backend.wait(f"hitl:decision:{request_id}", timeout_s=timeout_s)
        if val is not None:
            return bool(val)
        # Fall back to in-process event for single-process use.
        request = self._pending.get(request_id)
        if request is None:
            return None
        try:
            await asyncio.wait_for(request.event.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            return None
        return request.decision

    def decide(self, request_id: str, approved: bool) -> bool:
        # Signal via backend (visible to all workers).
        self._backend.signal(f"hitl:decision:{request_id}", int(approved))
        self._backend.delete(f"hitl:{request_id}")
        # Also resolve in-process for same-process callbacks.
        request = self._pending.get(request_id)
        if request is not None:
            request.decision = approved
            request.event.set()
            return True
        # Request came in on a different worker — that's fine.
        return True

    def discard(self, request_id: str) -> None:
        self._pending.pop(request_id, None)
        self._backend.delete(f"hitl:{request_id}")


class HTTPSlackMessageClient:
    """Minimal Slack Web API client using the standard library."""

    def __init__(self, bot_token: str):
        self.bot_token = bot_token

    async def post_approval(
        self,
        *,
        channel: str,
        request_id: str,
        action: str,
        context: dict[str, Any],
        public_url: str,
    ) -> None:
        await asyncio.to_thread(
            self._post_approval_sync,
            channel=channel,
            request_id=request_id,
            action=action,
            context=context,
            public_url=public_url,
        )

    def _post_approval_sync(
        self,
        *,
        channel: str,
        request_id: str,
        action: str,
        context: dict[str, Any],
        public_url: str,
    ) -> None:
        tenant = str(context.get("tenant", "unknown"))
        preview = str(context.get("output_preview", ""))[:240]
        body = {
            "channel": channel,
            "text": f"Veritrace approval requested for {action}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Veritrace approval requested*\n"
                            f"*Action:* `{action}`\n"
                            f"*Tenant:* `{tenant}`\n"
                            f"*Preview:* {preview or '_empty_'}"
                        ),
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Approve"},
                            "style": "primary",
                            "action_id": "veritrace_approve",
                            "value": request_id,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "style": "danger",
                            "action_id": "veritrace_deny",
                            "value": request_id,
                        },
                    ],
                },
            ],
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            "https://slack.com/api/chat.postMessage",
            data=data,
            headers={
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SlackApprovalError(f"failed to post Slack approval: {exc}") from exc
        if not payload.get("ok"):
            raise SlackApprovalError(
                f"Slack rejected approval message: {payload.get('error', 'unknown_error')}"
            )


class SlackHITLApprover:
    """Async callable compatible with HITLLayer's approver hook."""

    def __init__(
        self,
        *,
        bot_token: str,
        channel_id: str,
        signing_secret: str,
        public_url: str,
        registry: Optional[SlackApprovalRegistry] = None,
        client: Optional[SlackMessageClient] = None,
    ):
        self.channel_id = channel_id
        self.signing_secret = signing_secret
        self.public_url = public_url.rstrip("/")
        self.registry = registry or SlackApprovalRegistry()
        self.client = client or HTTPSlackMessageClient(bot_token)
        self.last_error: str = ""

    async def __call__(self, action: str, context: dict[str, Any]) -> Optional[bool]:
        request = self.registry.create(action, context)
        try:
            try:
                await self.client.post_approval(
                    channel=self.channel_id,
                    request_id=request.request_id,
                    action=action,
                    context=context,
                    public_url=self.public_url,
                )
            except SlackApprovalError as exc:
                self.last_error = str(exc)
                log.warning("Slack HITL approval post failed: %s", exc)
                return None
            self.last_error = ""
            return await self.registry.wait(request.request_id)
        finally:
            self.registry.discard(request.request_id)

    def handle_action_payload(self, payload: dict[str, Any]) -> tuple[bool, str]:
        actions = payload.get("actions") or []
        if not actions:
            raise SlackApprovalError("Slack payload did not include an action")
        action = actions[0]
        request_id = action.get("value")
        action_id = action.get("action_id")
        if not request_id:
            raise SlackApprovalError("Slack action did not include a request id")
        if action_id == "veritrace_approve":
            approved = True
        elif action_id == "veritrace_deny":
            approved = False
        else:
            raise SlackApprovalError(f"unknown Slack action: {action_id}")
        found = self.registry.decide(request_id, approved)
        return found, "approved" if approved else "denied"


def verify_slack_signature(
    *,
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    tolerance_s: int = 300,
) -> bool:
    """Validate Slack's v0 request signature."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > tolerance_s:
        return False
    base = b"v0:" + str(ts).encode("ascii") + b":" + body
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")
