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


# ── Finding #8: ESCALATE must route through HITL in the pipeline ──────────

def _escalating_guard():
    return ToolGuardLayer(policies=[
        ToolPolicy(
            name="wire_transfer",
            side_effect=SideEffect.PAYMENT,
            action=Verdict.ESCALATE,
            schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            detail="payments require human approval",
        )
    ])


@pytest.mark.asyncio
async def test_escalated_tool_does_not_complete_without_hitl_approval():
    """An ESCALATE verdict with no approver must idle and NOT complete —
    silence is never consent."""
    from pramagent.layers import HITLLayer

    armor = Pramagent(tool_guard=_escalating_guard(),
                      hitl=HITLLayer(timeout_s=0.2))
    response = await armor.run(
        "send the payment",
        tenant_id="bank", session_id="s1", action="wire_transfer",
        tool_name="wire_transfer", tool_arguments={"amount": 10},
    )

    assert response.blocked
    assert "requires human approval" in response.block_reason
    assert response.output == "[action not executed - awaiting/declined human approval]"
    assert response.trace.hitl_status == "idle"
    # the trace records both the escalation and the HITL decision
    layers = [(e.layer, e.decision) for e in response.trace.layer_events]
    assert ("ToolGuardLayer", "escalate") in layers
    assert ("HITLLayer", "idle") in layers


@pytest.mark.asyncio
async def test_escalated_tool_denied_by_human_does_not_complete():
    from pramagent.layers import HITLLayer

    async def deny(action, context):
        assert action == "tool:wire_transfer"
        assert context["tool_name"] == "wire_transfer"
        return False

    armor = Pramagent(tool_guard=_escalating_guard(),
                      hitl=HITLLayer(timeout_s=1.0, approver=deny))
    response = await armor.run(
        "send the payment",
        tenant_id="bank", session_id="s1", action="wire_transfer",
        tool_name="wire_transfer", tool_arguments={"amount": 10},
    )

    assert response.blocked
    assert response.trace.hitl_status == "denied"


@pytest.mark.asyncio
async def test_escalated_tool_completes_after_hitl_approval():
    """Approval lets the call proceed, with the approval event in the trace."""
    from pramagent.layers import HITLLayer

    async def approve(action, context):
        return True

    armor = Pramagent(tool_guard=_escalating_guard(),
                      hitl=HITLLayer(timeout_s=1.0, approver=approve))
    response = await armor.run(
        "send the payment",
        tenant_id="bank", session_id="s1", action="wire_transfer",
        tool_name="wire_transfer", tool_arguments={"amount": 10},
    )

    assert not response.blocked
    assert response.output            # provider completed
    approvals = [e for e in response.trace.layer_events
                 if e.layer == "HITLLayer" and e.decision == "approved"]
    assert approvals, "approved HITL event must be recorded in the trace"


# ── Finding #8: validate_output wired into the pipeline ───────────────────

@pytest.mark.asyncio
async def test_pipeline_withholds_output_with_exfil_markers():
    """Provider output containing secrets (AWS key) must be withheld by the
    ToolGuard output validation step."""
    from pramagent.providers import MockProvider

    leaky = MockProvider(scripted={
        "leak": "here are the creds AKIAABCDEFGHIJKLMNOP enjoy",
    })
    armor = Pramagent(provider=leaky)
    response = await armor.run("leak", tenant_id="t", session_id="s")

    assert response.output == "[output withheld by tool output validation]"
    events = [(e.layer, e.decision) for e in response.trace.layer_events]
    assert ("ToolGuardLayer.validate_output", "withheld") in events


@pytest.mark.asyncio
async def test_pipeline_passes_clean_output_through_validation():
    armor = Pramagent()
    response = await armor.run("hello there", tenant_id="t", session_id="s")

    assert "Acknowledged" in response.output
    events = [(e.layer, e.decision) for e in response.trace.layer_events]
    assert ("ToolGuardLayer.validate_output", "ok") in events


# ── Finding #10: concurrency safety ───────────────────────────────────────

def test_tool_guard_in_memory_state_is_thread_safe():
    """Concurrent evaluate() calls must not lose call-count or history
    updates (the in-memory path is now mutated under a lock)."""
    import threading

    guard = ToolGuardLayer(policies=[
        ToolPolicy(
            name="read_record",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            max_calls_per_session=10_000,
            schema={"type": "object"},
        )
    ], chain_window=10)

    n_threads, calls_per_thread = 8, 50

    def hammer():
        for _ in range(calls_per_thread):
            guard.evaluate("read_record", {}, tenant_id="t", session_id="s")

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    count, _window_started = guard._call_counts[("t", "s", "read_record")]
    assert count == n_threads * calls_per_thread
    history = guard._side_effect_history[("t", "s")]
    assert len(history) == 10                       # bounded to chain_window
    assert all(h == "read" for h in history)


def test_inprocess_backend_history_append_bounds_and_returns_window():
    backend = InProcessBackend()
    for effect in ["read", "write", "read", "payment"]:
        window = backend.history_append("k", effect, max_len=3)
    assert window == ["write", "read", "payment"]   # trimmed to max_len


def test_tool_guard_uses_backend_atomic_history_append():
    backend = InProcessBackend()
    guard = ToolGuardLayer(policies=[
        ToolPolicy(name="read_record", side_effect=SideEffect.READ,
                   action=Verdict.ALLOW, schema={"type": "object"}),
    ], backend=backend, chain_window=5)

    for _ in range(7):
        guard.evaluate("read_record", {}, tenant_id="t", session_id="s")

    key = guard._backend_key("history", "t", "s")
    assert backend.get(key) == ["read"] * 5         # trimmed atomically
    # in-memory dict untouched when a backend is present
    assert guard._side_effect_history[("t", "s")] == []
