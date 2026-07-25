from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from unison_common import AuthenticatedTarget, ExpressionPlanRequest, SemanticObservation


def test_expression_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ExpressionPlanRequest(person_id="p", session_id="s", capabilities=[], renderer="both")


def test_observation_preserves_source_and_distrust():
    observation = SemanticObservation(
        observation_id="o1", source_type="accessibility-tree", source_id="page",
        state_version="7", confidence=.9, content={"role": "form"},
        injection_signals=["ignore policy"],
    )
    assert observation.trust == "untrusted"


def test_authenticated_target_rejects_expired_binding():
    with pytest.raises(ValidationError):
        AuthenticatedTarget(
            capability="submit", target_id="form-1", person_id="p", state_version="1",
            authority_token_hash="a" * 64,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
