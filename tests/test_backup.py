from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from jsonschema import Draft202012Validator

from unison_common.backup import (
    BackupCrypto,
    BackupManifest,
    ChunkReference,
    ScopeKind,
    SignedManifestEnvelope,
    SnapshotLineage,
)


def _manifest(opaque_scope_id: str, chunk_id: str) -> BackupManifest:
    return BackupManifest(
        snapshot_id="snapshot-1",
        opaque_scope_id=opaque_scope_id,
        scope_kind=ScopeKind.PERSON,
        scope_id="person-alice",
        key_epoch=1,
        lineage=SnapshotLineage(
            sequence=1,
            created_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
        ),
        chunks=(
            ChunkReference(
                object_id=chunk_id,
                plaintext_sha256=hashlib.sha256(b"private").hexdigest(),
                plaintext_size=7,
                stored_size=100,
                ordinal=0,
            ),
        ),
        provenance=("unison-context:v2",),
    )


def test_chunk_encryption_is_scope_isolated_and_authenticated():
    alice = BackupCrypto.generate_scope_key()
    bob = BackupCrypto.generate_scope_key()
    opaque = BackupCrypto.opaque_scope_id(alice, "person-alice")
    chunk = BackupCrypto.encrypt_chunk(
        b"private",
        scope_key=alice,
        opaque_scope_id=opaque,
        key_epoch=1,
    )
    assert BackupCrypto.decrypt_chunk(
        chunk,
        scope_key=alice,
        opaque_scope_id=opaque,
    ) == b"private"
    with pytest.raises(InvalidTag):
        BackupCrypto.decrypt_chunk(
            chunk,
            scope_key=bob,
            opaque_scope_id=opaque,
        )


def test_manifest_signature_encryption_and_checkpoint_detect_tampering():
    scope_key = BackupCrypto.generate_scope_key()
    opaque = BackupCrypto.opaque_scope_id(scope_key, "person-alice")
    signing_key = BackupCrypto.generate_signing_key()
    envelope = BackupCrypto.encrypt_and_sign_manifest(
        _manifest(opaque, "object-1"),
        scope_key=scope_key,
        signing_key=signing_key,
    )
    public_key = BackupCrypto.public_key_bytes(signing_key.public_key())
    restored = BackupCrypto.verify_and_decrypt_manifest(
        envelope,
        scope_key=scope_key,
        trusted_public_key=public_key,
    )
    assert restored.scope_id == "person-alice"
    BackupCrypto.verify_checkpoint(envelope, BackupCrypto.checkpoint(envelope))

    tampered = envelope.model_copy(update={"ciphertext": envelope.ciphertext + "A"})
    with pytest.raises(ValueError, match="signature"):
        BackupCrypto.verify_and_decrypt_manifest(
            tampered,
            scope_key=scope_key,
            trusted_public_key=public_key,
        )


def test_checkpoint_rejects_provider_rollback_and_fork():
    scope_key = BackupCrypto.generate_scope_key()
    opaque = BackupCrypto.opaque_scope_id(scope_key, "person-alice")
    signing_key = BackupCrypto.generate_signing_key()
    first = BackupCrypto.encrypt_and_sign_manifest(
        _manifest(opaque, "object-1"),
        scope_key=scope_key,
        signing_key=signing_key,
    )
    checkpoint = BackupCrypto.checkpoint(first)
    rolled_back = first.model_copy(
        update={"sequence": 0, "manifest_digest": "0" * 64}
    ).model_copy(update={"sequence": 1})
    older_checkpoint = checkpoint.model_copy(update={"sequence": 2})
    with pytest.raises(ValueError, match="rollback"):
        BackupCrypto.verify_checkpoint(rolled_back, older_checkpoint)
    forked = SignedManifestEnvelope.model_validate(
        first.model_dump() | {"manifest_digest": "f" * 64}
    )
    with pytest.raises(ValueError, match="forked"):
        BackupCrypto.verify_checkpoint(forked, checkpoint)


def test_recovery_capsule_requires_person_controlled_code():
    code = BackupCrypto.generate_recovery_code()
    capsule = BackupCrypto.seal_recovery_capsule(b"person-root-key", code)
    assert BackupCrypto.open_recovery_capsule(capsule, code) == b"person-root-key"
    wrong = BackupCrypto.generate_recovery_code()
    with pytest.raises(InvalidTag):
        BackupCrypto.open_recovery_capsule(capsule, wrong)


def test_recovery_code_checksum_rejects_transcription_error():
    code = BackupCrypto.generate_recovery_code()
    replacement = "A" if code[-1] != "A" else "B"
    with pytest.raises(ValueError, match="checksum"):
        BackupCrypto.seal_recovery_capsule(b"payload", code[:-1] + replacement)


def test_canonical_and_packaged_schema_match_and_validate_manifest():
    root = Path(__file__).resolve().parents[1]
    canonical = json.loads(
        (root / "schemas" / "provider-blind-backup.v1.schema.json").read_text()
    )
    packaged = json.loads(
        (
            root
            / "src"
            / "unison_common"
            / "schemas"
            / "provider-blind-backup.v1.schema.json"
        ).read_text()
    )
    assert canonical == packaged
    Draft202012Validator(canonical).validate(
        _manifest("opaque-scope-identifier-123", "opaque-object-identifier").model_dump(
            mode="json"
        )
    )
