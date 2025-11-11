import os
import logging
import pytest
from opentelemetry import trace
from opentelemetry.propagate import inject

from unison_common.tracing import initialize_tracing, TracingConfig


def test_resource_attributes_and_sampling_one(monkeypatch):
    monkeypatch.setenv("OTEL_SERVICE_NAME", "svc-a")
    monkeypatch.setenv("OTEL_SERVICE_VERSION", "9.9.9")
    monkeypatch.setenv("OTEL_ENVIRONMENT", "staging")
    monkeypatch.setenv("OTEL_SAMPLE_RATE", "1.0")

    initialize_tracing(TracingConfig())
    provider = trace.get_tracer_provider()

    # Resource attributes
    res = getattr(provider, "resource", None)
    assert res is not None
    attrs = res.attributes
    assert attrs.get("service.name") == "svc-a"
    assert attrs.get("service.version") == "9.9.9"
    assert attrs.get("deployment.environment") == "staging"

    # Sampling 1.0 should record
    with trace.get_tracer(__name__).start_as_current_span("t1") as span:
        assert span.is_recording() is True


def test_propagator_b3_headers(monkeypatch):
    monkeypatch.setenv("OTEL_PROPAGATOR", "b3")
    initialize_tracing(TracingConfig())

    headers = {}
    # Ensure an active span exists so inject produces headers
    with trace.get_tracer(__name__).start_as_current_span("p"): 
        inject(headers)
    # B3 should set X-B3-TraceId and X-B3-SpanId
    # Keys casing may vary; check lower
    lower = {k.lower(): v for k, v in headers.items()}
    assert any(k in lower for k in ["x-b3-traceid", "x-b3-trace-id"])  # different libs vary
    assert any(k in lower for k in ["x-b3-spanid", "x-b3-span-id"])  # different libs vary
