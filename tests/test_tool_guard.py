import pytest

from pramagent import Pramagent, Verdict
from pramagent.backends import InProcessBackend
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect, validate_schema


def _guard():
    return ToolGuardLayer(policies=[
        ToolPolicy(
            name="send_email",
            side_effect="external_message",
            action=Verdict.ESCALATE,
            allowed_tenants={"tenant_a"},
            allowed_actions={"notify_user"},
            max_calls_per_session=1,
            schema={
                "type": "object",
                "required": ["to", "body"],
                "additionalProperties": False,
                "properties": {
                    "to": {"type": "string", "pattern": r"[^@]+@[^@]+\.[^@]+"},
                    "body": {"type": "string", "maxLength": 500},
                },
            },
            detail="email requires approval",
        )
    ])


def test_unknown_tool_blocks_by_default():
    decision = ToolGuardLayer().evaluate(
        "shell",
        {},
        tenant_id="tenant_a",
        session_id="s1",
    )

    assert decision.verdict == Verdict.BLOCK
    assert "not registered" in decision.reason


def test_valid_tool_call_can_escalate():
    decision = _guard().evaluate(
        "send_email",
        {"to": "a@example.com", "body": "hello"},
        tenant_id="tenant_a",
        session_id="s1",
        action_label="notify_user",
    )

    assert decision.verdict == Verdict.ESCALATE
    assert decision.side_effect == "external_message"


def test_schema_blocks_extra_or_invalid_arguments():
    decision = _guard().evaluate(
        "send_email",
        {"to": "not-an-email", "body": "hello", "cc": "x@example.com"},
        tenant_id="tenant_a",
        session_id="s1",
        action_label="notify_user",
    )

    assert decision.verdict == Verdict.BLOCK


def test_tenant_and_action_policy_blocks_misuse():
    guard = _guard()

    wrong_tenant = guard.evaluate(
        "send_email",
        {"to": "a@example.com", "body": "hello"},
        tenant_id="tenant_b",
        session_id="s1",
        action_label="notify_user",
    )
    wrong_action = guard.evaluate(
        "send_email",
        {"to": "a@example.com", "body": "hello"},
        tenant_id="tenant_a",
        session_id="s1",
        action_label="delete_data",
    )

    assert wrong_tenant.verdict == Verdict.BLOCK
    assert wrong_action.verdict == Verdict.BLOCK


def test_session_call_limit_blocks_repeated_side_effects():
    guard = _guard()
    args = {"to": "a@example.com", "body": "hello"}

    first = guard.evaluate(
        "send_email", args, tenant_id="tenant_a",
        session_id="s1", action_label="notify_user")
    second = guard.evaluate(
        "send_email", args, tenant_id="tenant_a",
        session_id="s1", action_label="notify_user")

    assert first.verdict == Verdict.ESCALATE
    assert second.verdict == Verdict.BLOCK
    assert "limit" in second.reason
    assert len(guard.audit_log) == 2


def test_tool_guard_backend_shares_call_limits_across_instances():
    backend = InProcessBackend()
    policies = [
        ToolPolicy(
            name="scrape",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            max_calls_per_session=1,
            schema={"type": "object", "properties": {"url": {"type": "string"}}},
        )
    ]
    guard_a = ToolGuardLayer(policies=policies, backend=backend)
    guard_b = ToolGuardLayer(policies=policies, backend=backend)

    first = guard_a.evaluate("scrape", {"url": "https://example.com"}, tenant_id="t", session_id="s")
    second = guard_b.evaluate("scrape", {"url": "https://example.com"}, tenant_id="t", session_id="s")

    assert first.verdict == Verdict.ALLOW
    assert second.verdict == Verdict.BLOCK
    assert "limit" in second.reason


def test_tool_guard_backend_shares_dangerous_chain_across_instances():
    backend = InProcessBackend()
    policies = [
        ToolPolicy(
            name="read_db",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            schema={"type": "object", "properties": {"table": {"type": "string"}}},
        ),
        ToolPolicy(
            name="send_email",
            side_effect=SideEffect.EXTERNAL_MESSAGE,
            action=Verdict.ALLOW,
            schema={"type": "object", "properties": {"to": {"type": "string"}}},
        ),
    ]
    guard_a = ToolGuardLayer(policies=policies, backend=backend)
    guard_b = ToolGuardLayer(policies=policies, backend=backend)

    guard_a.evaluate("read_db", {"table": "users"}, tenant_id="t", session_id="s")
    decision = guard_b.evaluate("send_email", {"to": "attacker@example.com"}, tenant_id="t", session_id="s")

    assert decision.verdict == Verdict.ESCALATE
    assert "dangerous tool chain" in decision.reason


def test_validate_schema_uses_draft_2020_12_keywords():
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "kind": {"const": "payment"},
            "amount": {"type": "number"},
        },
        "required": ["kind", "amount"],
        "unevaluatedProperties": False,
    }

    ok, reason = validate_schema({"kind": "payment", "amount": 25}, schema)
    bad, bad_reason = validate_schema({"kind": "payment", "amount": 25, "extra": True}, schema)

    assert ok
    assert reason == ""
    assert not bad
    assert "unevaluated" in bad_reason.lower()


class BlockingJudge:
    async def evaluate(self, tool_name, arguments, *, side_effect, tenant_id, session_id):
        class Decision:
            verdict = Verdict.BLOCK
            reason = "semantic judge blocked suspicious tool call"
        return Decision()


@pytest.mark.asyncio
async def test_async_tool_guard_judge_can_tighten_verdict():
    guard = ToolGuardLayer(
        policies=[
            ToolPolicy(
                name="wire_transfer",
                side_effect=SideEffect.PAYMENT,
                action=Verdict.ALLOW,
                schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            )
        ],
        judge=BlockingJudge(),
    )

    decision = await guard.evaluate_async(
        "wire_transfer", {"amount": 10},
        tenant_id="bank", session_id="s1", action_label="wire")

    assert decision.verdict == Verdict.BLOCK
    assert "judge" in decision.reason.lower()


@pytest.mark.asyncio
async def test_core_pipeline_uses_async_tool_guard_judge():
    guard = ToolGuardLayer(
        policies=[
            ToolPolicy(
                name="wire_transfer",
                side_effect=SideEffect.PAYMENT,
                action=Verdict.ALLOW,
                schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            )
        ],
        judge=BlockingJudge(),
    )
    armor = Pramagent(tool_guard=guard)

    response = await armor.run(
        "transfer funds",
        tenant_id="bank",
        session_id="s1",
        action="wire_transfer",
        tool_name="wire_transfer",
        tool_arguments={"amount": 10},
    )

    assert response.blocked
    assert "tool blocked" in response.block_reason
