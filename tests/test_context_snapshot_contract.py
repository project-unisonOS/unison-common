import time

from unison_common.contracts.v1 import ContextSnapshot


def test_context_snapshot_contract_roundtrip():
    snap = ContextSnapshot(person_id="p1", profile={"name": "A"}, dashboard=None, fetched_at_unix_ms=int(time.time() * 1000))
    dumped = snap.model_dump(mode="json")
    assert dumped["schema_version"] == "context-snapshot.v1"
    assert dumped["person_id"] == "p1"

