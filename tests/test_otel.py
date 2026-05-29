import pytest

from veritrace.layers import ObservabilityLayer
from veritrace.otel import OpenTelemetryExporter, OpenTelemetryNotInstalled


def test_otel_exporter_registers_against_installed_api():
    pytest.importorskip("opentelemetry")
    obs = ObservabilityLayer()
    obs.start_call()
    obs.record_result(blocked=True, latency_ms=12.5, block_reason="input too large")

    exporter = OpenTelemetryExporter(obs)

    assert len(exporter._callbacks) == 8
    assert obs.report()["oversize_blocked"] == 1


def test_otel_exporter_failure_type_exists():
    assert issubclass(OpenTelemetryNotInstalled, RuntimeError)
