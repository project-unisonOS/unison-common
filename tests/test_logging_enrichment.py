import json
import logging
import pytest
from unison_common.logging import log_json, configure_logging
from unison_common.tracing import initialize_tracing
from opentelemetry import trace
from opentelemetry.trace import SpanKind


def get_last_log_json(caplog):
    for rec in reversed(caplog.records):
        try:
            return json.loads(rec.getMessage())
        except Exception:
            continue
    return {}


def test_log_json_enriches_trace_fields(caplog):
    caplog.set_level(logging.INFO)
    initialize_tracing()

    logger = configure_logging("test")
    with trace.get_tracer(__name__).start_as_current_span("log-span", kind=SpanKind.INTERNAL):
        log_json(logging.INFO, "test_event", custom="ok")

    payload = get_last_log_json(caplog)
    assert payload.get("event") == "test_event"
    # Enriched fields
    assert isinstance(payload.get("request_id"), str) and len(payload.get("request_id")) > 0
    assert payload.get("trace_id") == payload.get("request_id")
    assert isinstance(payload.get("span_id"), str) and len(payload.get("span_id")) > 0
    assert isinstance(payload.get("traceparent"), str) and len(payload.get("traceparent")) > 0
