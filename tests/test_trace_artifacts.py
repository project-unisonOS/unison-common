import json

from unison_common.trace_artifacts import TraceRecorder, TraceSpanStatus


def test_trace_recorder_spans_and_events(tmp_path):
    recorder = TraceRecorder(service="test-service", attrs={"foo": "bar"})
    recorder.emit_event("input_received")
    with recorder.span("planner_started"):
        recorder.emit_event("planner_ended", {"ok": True})

    out = recorder.write_json(tmp_path / "trace.json")
    data = json.loads(out.read_text(encoding="utf-8"))

    assert data["schema_version"] == "trace-artifact.v1"
    assert data["service"] == "test-service"
    assert data["attrs"]["foo"] == "bar"
    assert len(data["events"]) == 2
    assert len(data["spans"]) == 1
    span = data["spans"][0]
    assert span["name"] == "planner_started"
    assert span["status"] == TraceSpanStatus.OK.value
    assert span["end_monotonic_ns"] is not None
    assert span["duration_ms"] >= 0.0


def test_trace_recorder_nested_parent_span():
    recorder = TraceRecorder(service="test-service")
    with recorder.span("outer") as outer:
        with recorder.span("inner"):
            pass

    spans = recorder.to_dict()["spans"]
    assert len(spans) == 2
    inner = next(s for s in spans if s["name"] == "inner")
    assert inner["parent_span_id"] == outer.span_id

