from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from unison_common.principal import (
    PrincipalKind,
    assert_identity_hints,
    bind_identity,
    partition_key,
    principal_context_from_claims,
    redact_principal_for_log,
)


def claims(**updates):
    now = int(time.time())
    value = {
        "sub": "principal-alice",
        "principal_id": "principal-alice",
        "principal_kind": "person",
        "person_id": "person-alice",
        "assistant_instance_id": "assistant-alice",
        "household_id": "household-one",
        "membership_id": "membership-alice",
        "roles": ["adult-member"],
        "scope": "assistant:use profile:read",
        "aud": ["orchestrator", "context", "storage"],
        "auth_method": "passkey",
        "assurance": "high",
        "session_id": "session-one",
        "key_handle": "key-alice",
        "credential_namespace": "cred-alice",
        "data_namespace": "data-alice",
        "cache_namespace": "cache-alice",
        "index_namespace": "index-alice",
        "jti": "token-one",
        "iat": now - 1,
        "exp": now + 300,
    }
    value.update(updates)
    return value


def test_person_context_requires_all_isolation_handles():
    context = principal_context_from_claims(claims(), expected_audience="context")
    assert context.principal_kind is PrincipalKind.PERSON
    assert context.person_id == "person-alice"
    assert context.data_namespace == "data-alice"


def test_wrong_audience_and_incomplete_person_are_rejected():
    with pytest.raises(ValueError, match="audience"):
        principal_context_from_claims(claims(), expected_audience="payments")
    with pytest.raises(ValueError, match="authority fields"):
        principal_context_from_claims(claims(key_handle=None))


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("person_id", "person-bob"),
        ("user_id", "person-bob"),
        ("principal_id", "principal-bob"),
        ("assistant_instance_id", "assistant-bob"),
        ("assistant_id", "assistant-bob"),
        ("household_id", "household-two"),
        ("membership_id", "membership-bob"),
        ("channel_identity_id", "channel-bob"),
    ],
)
def test_forged_identity_hint_matrix_denies(field, forged):
    context = principal_context_from_claims(claims())
    with pytest.raises(HTTPException) as denied:
        assert_identity_hints(context, {field: forged})
    assert denied.value.status_code == 403


def test_binding_stamps_trusted_identity_and_partitions_keys():
    context = principal_context_from_claims(claims())
    bound = bind_identity({"person_id": "person-alice", "value": 3}, context)
    assert bound["principal_id"] == "principal-alice"
    assert bound["assistant_instance_id"] == "assistant-alice"
    assert partition_key(context, "profile", "primary") == "data-alice:profile:primary"


def test_log_view_excludes_key_and_credential_handles():
    context = principal_context_from_claims(claims())
    logged = redact_principal_for_log(context)
    assert "key_handle" not in logged
    assert "credential_namespace" not in logged
    assert "data-alice" not in repr(logged)
