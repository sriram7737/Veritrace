"""
pramagent.layers.observability
==============================
Lightweight metrics collection. Counts, blocked rate, p50/p95 latency.
This is the minimum a SRE would want exposed; production deployments would
also export these to OpenTelemetry / Prometheus. The interface stays small
so an exporter can be bolted on without touching the orchestrator.
"""
from __future__ import annotations

from bisect import insort


class ObservabilityLayer:
    """In-process metrics. Bounded latency window so memory stays flat."""

    def __init__(self, latency_window: int = 1000) -> None:
        self.total_calls = 0
        self.blocked_calls = 0
        self.injection_blocked = 0
        self.oversize_blocked = 0
        self._latencies: list[float] = []          # sorted, bounded
        self._latency_window = latency_window

    def start_call(self) -> None:
        self.total_calls += 1

    def record_result(self, *, blocked: bool, latency_ms: float,
                      block_reason: str = "") -> None:
        if blocked:
            self.blocked_calls += 1
            if "injection" in block_reason.lower():
                self.injection_blocked += 1
            elif "size" in block_reason.lower() or "too large" in block_reason.lower():
                self.oversize_blocked += 1
        # bounded ordered insert for percentile calc
        if len(self._latencies) >= self._latency_window:
            self._latencies.pop(0)
        insort(self._latencies, latency_ms)

    def _pct(self, p: float) -> float:
        if not self._latencies:
            return 0.0
        idx = min(int(p * len(self._latencies)), len(self._latencies) - 1)
        return self._latencies[idx]

    def report(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "blocked_calls": self.blocked_calls,
            "injection_blocked": self.injection_blocked,
            "oversize_blocked": self.oversize_blocked,
            "block_rate": (self.blocked_calls / self.total_calls
                           if self.total_calls else 0.0),
            "p50_latency_ms": round(self._pct(0.50), 2),
            "p95_latency_ms": round(self._pct(0.95), 2),
            "p99_latency_ms": round(self._pct(0.99), 2),
        }
