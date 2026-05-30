"""
veritrace.backends
==================
Pluggable backend adapters for distributed state.

In-process defaults work fine for single-process deployments and tests.
Switch to Redis-backed adapters for multi-worker / multi-instance production.

Usage::

    from veritrace.backends import RedisBackend
    from veritrace.hitl.slack import SlackApprovalRegistry
    from veritrace.ratelimit import TokenBucket

    backend = RedisBackend.from_url("redis://localhost:6379/0")
    registry = SlackApprovalRegistry(backend=backend)
    limiter  = TokenBucket(capacity=100, refill_per_sec=10, backend=backend)
"""
from .redis_backend import RedisBackend, InProcessBackend, AbstractBackend

__all__ = ["AbstractBackend", "InProcessBackend", "RedisBackend"]
