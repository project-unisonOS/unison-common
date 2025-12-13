import time

from unison_common.contracts.v1 import EventGraphAppend, EventGraphEvent, EventGraphQuery


def test_event_graph_event_and_append_contracts():
    evt = EventGraphEvent(
        event_id="e1",
        trace_id="t1",
        ts_unix_ms=int(time.time() * 1000),
        event_type="input_received",
        attrs={"modality": "text"},
        payload={"text": "hi"},
    )
    app = EventGraphAppend(trace_id="t1", session_id="s1", person_id="p1", events=[evt])
    dumped = app.model_dump(mode="json")
    assert dumped["schema_version"] == "event-graph-append.v1"
    assert dumped["events"][0]["schema_version"] == "event-graph-event.v1"


def test_event_graph_query_defaults():
    q = EventGraphQuery(trace_id="t1")
    dumped = q.model_dump(mode="json")
    assert dumped["limit"] == 500

