"""Optional OpenTelemetry metrics export."""
from __future__ import annotations

from typing import Any

from .layers import ObservabilityLayer


class OpenTelemetryNotInstalled(RuntimeError):
    pass


class OpenTelemetryExporter:
    """Exports the in-process observability snapshot as OTel gauges.

    The dependency is imported lazily so core Pramagent stays zero-dependency.
    Install with `pip install -e ".[otel]"`.
    """

    def __init__(self, observability: ObservabilityLayer,
                 *, meter_name: str = "pramagent") -> None:
        try:
            from opentelemetry import metrics
        except ImportError as exc:
            raise OpenTelemetryNotInstalled(
                "OpenTelemetry metrics are not installed; install pramagent[otel]"
            ) from exc

        self.observability = observability
        self.meter = metrics.get_meter(meter_name)
        self._callbacks: list[Any] = []
        self._register("pramagent.calls.total", "Total calls", "1", "total_calls")
        self._register("pramagent.calls.blocked", "Blocked calls", "1", "blocked_calls")
        self._register("pramagent.calls.block_rate", "Blocked call ratio", "1", "block_rate")
        self._register("pramagent.latency.p50", "p50 latency", "ms", "p50_latency_ms")
        self._register("pramagent.latency.p95", "p95 latency", "ms", "p95_latency_ms")
        self._register("pramagent.latency.p99", "p99 latency", "ms", "p99_latency_ms")
        self._register("pramagent.blocks.injection", "Injection blocks", "1", "injection_blocked")
        self._register("pramagent.blocks.oversize", "Oversize blocks", "1", "oversize_blocked")

    def _register(self, name: str, description: str, unit: str, field: str) -> None:
        def callback(options):
            from opentelemetry.metrics import Observation
            snapshot = self.observability.report()
            return [Observation(snapshot.get(field, 0))]

        self._callbacks.append(callback)
        self.meter.create_observable_gauge(
            name,
            callbacks=[callback],
            description=description,
            unit=unit,
        )
