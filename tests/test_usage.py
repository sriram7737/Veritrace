from veritrace.usage import UsageLimits, UsageTracker


def test_call_quota_blocks_after_limit():
    tracker = UsageTracker(UsageLimits(max_calls=2, window_s=60))

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_call("acme").allowed
    blocked = tracker.reserve_call("acme")

    assert not blocked.allowed
    assert "call quota" in blocked.reason
    snap = tracker.snapshot("acme")
    assert snap.calls == 2
    assert snap.remaining_calls() == 0


def test_quota_window_resets():
    now = [100.0]
    tracker = UsageTracker(
        UsageLimits(max_calls=1, window_s=10),
        now_fn=lambda: now[0],
    )

    assert tracker.reserve_call("acme").allowed
    assert not tracker.reserve_call("acme").allowed

    now[0] = 111.0
    assert tracker.reserve_call("acme").allowed
    assert tracker.snapshot("acme").calls == 1


def test_tool_validation_quota_is_separate_from_call_quota():
    tracker = UsageTracker(UsageLimits(max_calls=10, max_tool_validations=1))

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("acme").allowed
    blocked = tracker.reserve_tool_validation("acme")

    assert not blocked.allowed
    assert "tool-validation quota" in blocked.reason
    assert tracker.snapshot("acme").calls == 1


def test_cost_quota_blocks_future_work_after_spend_is_recorded():
    tracker = UsageTracker(UsageLimits(max_cost_usd=0.01))

    assert tracker.reserve_call("acme").allowed
    tracker.record_cost("acme", 0.012)
    blocked = tracker.reserve_call("acme")

    assert not blocked.allowed
    assert "cost quota" in blocked.reason
    assert tracker.snapshot("acme").cost_usd == 0.012


def test_disabled_tracker_allows_without_limits():
    tracker = UsageTracker()

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("acme").allowed
    assert not tracker.enabled
