"""
veritrace.ratelimit
===================
Per-key token-bucket rate limiter for the HTTP service.

This is in-process and intentionally simple. It refills a bucket per key at a
fixed rate and rejects with HTTP 429 when empty. For multi-process or
multi-instance deployments, swap the bucket store for Redis — the interface
stays the same.

Rate keys
---------
When auth is enabled, the key is the tenant id. When auth is disabled, the key
is the client IP. Both come from the FastAPI request via the dependency wired
in the app factory.
"""
from __future__ import annotations

import time
from threading import Lock


class TokenBucket:
    """One bucket per rate key. Thread-safe in-process implementation."""

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}   # key -> (tokens, last_refill_ts)
        self._lock = Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Consume `cost` tokens for `key`. Returns (allowed, retry_after_seconds)."""
        now = time.time()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            # refill
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens >= cost:
                self._buckets[key] = (tokens - cost, now)
                return True, 0.0
            # not enough — how long until we have `cost` tokens?
            deficit = cost - tokens
            retry = deficit / self.refill_per_sec
            self._buckets[key] = (tokens, now)
            return False, retry
