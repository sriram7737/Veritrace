"""
pramagent.ratelimit
===================
Per-key token-bucket rate limiter for the HTTP service.

Default: in-process, thread-safe (InProcessBackend). For multi-worker
deployments pass a RedisBackend so rate limits are shared across instances::

    from pramagent.backends import RedisBackend
    from pramagent.ratelimit import TokenBucket

    limiter = TokenBucket(
        capacity=100,
        refill_per_sec=10,
        backend=RedisBackend.from_url(os.environ["REDIS_URL"]),
    )

Rate keys
---------
When auth is enabled the key is the tenant id. When auth is disabled the key
is the client IP. Both come from the FastAPI request via the dependency wired
in the app factory.
"""
from __future__ import annotations

from typing import Optional, Any


class TokenBucket:
    """Token-bucket rate limiter. Backend is pluggable (in-process or Redis)."""

    def __init__(
        self,
        capacity: int,
        refill_per_sec: float,
        backend: Optional[Any] = None,
    ) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        if backend is None:
            from .backends import InProcessBackend
            backend = InProcessBackend()
        self._backend = backend

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Consume cost tokens for key. Returns (allowed, retry_after_seconds)."""
        return self._backend.tb_allow(
            key,
            capacity=float(self.capacity),
            refill_per_sec=self.refill_per_sec,
            cost=cost,
        )
