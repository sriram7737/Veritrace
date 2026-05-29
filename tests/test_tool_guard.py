from veritrace import Verdict
from veritrace.layers import ToolGuardLayer, ToolPolicy


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
