import os
import tempfile
import time
from pathlib import Path

import pytest

from unison_common.baton import BatonError, BatonService, BatonKeyStore


def test_issue_and_verify_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "baton.pem")
        service = BatonService(BatonKeyStore(Path(key_path)))
        token = service.issue(
            subject="person-123",
            scopes=["ingest", "replay"],
            audience=["orchestrator"],
            issuer="test",
            ttl_seconds=5,
        )
        baton = service.verify(token, required_scopes=["ingest"], audience="orchestrator")
        assert baton.subject == "person-123"
        assert "ingest" in baton.scopes


def test_scope_mismatch_raises():
    service = BatonService()
    token = service.issue(subject="p", scopes=["foo"], audience=["svc"])
    with pytest.raises(BatonError):
        service.verify(token, required_scopes=["bar"])


def test_expired_baton_rejected():
    service = BatonService()
    token = service.issue(subject="p", scopes=["foo"], audience=["svc"], ttl_seconds=1)
    time.sleep(1.1)
    with pytest.raises(BatonError):
        service.verify(token)


def test_append_provenance_updates_token():
    service = BatonService()
    token = service.issue(subject="p", scopes=["foo"], audience=["svc"])
    updated = service.append_provenance(token, {"service": "orchestrator"})
    baton = service.verify(updated)
    assert {"service": "orchestrator"} in baton.provenance
