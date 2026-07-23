"""Provider-blind backup v1 contracts and cryptographic primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field, model_validator


FORMAT_VERSION = "unison-backup-v1"
_RECOVERY_PREFIX = "UNISON1"
_CODE_RE = re.compile(r"^[A-Z2-7]+$")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(model: BaseModel | dict[str, Any]) -> bytes:
    """Return the exact deterministic representation used for signatures."""

    value = model.model_dump(mode="json") if isinstance(model, BaseModel) else model
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class BackupModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScopeKind(StrEnum):
    PERSON = "person"
    SHARED_SPACE = "shared-space"
    DEVICE = "device"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    CORRUPT = "corrupt"
    INCOMPLETE = "incomplete"
    ROLLED_BACK = "rolled-back"
    UNANCHORED = "unanchored"


class RestoreStatus(StrEnum):
    PLANNED = "planned"
    STAGING = "staging"
    VERIFIED = "verified"
    ACTIVATED = "activated"
    CANCELLED = "cancelled"
    FAILED = "failed"


class BackendCapabilities(BackupModel):
    backend_type: str
    conditional_write: bool
    range_read: bool
    resumable_transfer: bool
    delete: bool
    list_prefix: bool
    server_side_encryption_required: bool = False


class WrappedKeyReference(BackupModel):
    algorithm: str = "AES-256-GCM"
    key_epoch: int = Field(ge=1)
    nonce: str
    ciphertext: str


class EncryptedChunk(BackupModel):
    format_version: str = FORMAT_VERSION
    object_id: str
    nonce: str
    ciphertext: str
    wrapped_data_key: WrappedKeyReference


class ChunkReference(BackupModel):
    object_id: str
    plaintext_sha256: str
    plaintext_size: int = Field(ge=0)
    stored_size: int = Field(ge=0)
    ordinal: int = Field(ge=0)


class Tombstone(BackupModel):
    tombstone_id: str
    target_type: str
    target_id: str
    scope_kind: ScopeKind
    scope_id: str
    deleted_at: datetime
    reason: str
    cryptographic_erasure: bool


class SnapshotLineage(BackupModel):
    sequence: int = Field(ge=1)
    parent_manifest_digest: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def validate_parent(self) -> "SnapshotLineage":
        if self.sequence == 1 and self.parent_manifest_digest is not None:
            raise ValueError("the first manifest cannot have a parent")
        if self.sequence > 1 and not self.parent_manifest_digest:
            raise ValueError("incremental manifests require a parent digest")
        return self


class BackupManifest(BackupModel):
    format_version: str = FORMAT_VERSION
    snapshot_id: str
    opaque_scope_id: str
    scope_kind: ScopeKind
    scope_id: str
    key_epoch: int = Field(ge=1)
    lineage: SnapshotLineage
    chunks: tuple[ChunkReference, ...]
    tombstones: tuple[Tombstone, ...] = ()
    provenance: tuple[str, ...] = ()
    retention_until: datetime | None = None


class SignedManifestEnvelope(BackupModel):
    format_version: str = FORMAT_VERSION
    opaque_scope_id: str
    sequence: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    nonce: str
    ciphertext: str
    signer_public_key: str
    signature: str
    manifest_digest: str

    def signing_payload(self) -> bytes:
        return canonical_json(
            {
                "ciphertext": self.ciphertext,
                "format_version": self.format_version,
                "key_epoch": self.key_epoch,
                "nonce": self.nonce,
                "opaque_scope_id": self.opaque_scope_id,
                "sequence": self.sequence,
            }
        )


class ManifestCheckpoint(BackupModel):
    format_version: str = FORMAT_VERSION
    opaque_scope_id: str
    sequence: int = Field(ge=1)
    manifest_digest: str
    signer_fingerprint: str
    lineage_floor_sequence: int = Field(default=1, ge=1)
    lineage_floor_parent_digest: str | None = None
    witnessed_at: datetime = Field(default_factory=_utcnow)


class VerificationRecord(BackupModel):
    verification_id: str
    opaque_scope_id: str
    snapshot_id: str | None
    checked_at: datetime = Field(default_factory=_utcnow)
    status: VerificationStatus
    checked_objects: int = Field(ge=0)
    detail: str
    resumed: bool = False


class RestorePlan(BackupModel):
    plan_id: str
    opaque_scope_id: str
    snapshot_id: str
    manifest_digest: str
    target_device_id: str
    status: RestoreStatus = RestoreStatus.PLANNED
    total_objects: int = Field(ge=0)
    completed_objects: int = Field(default=0, ge=0)
    dry_run: bool = True
    anchor_verified: bool = False
    cancellation_available: bool = True


class RecoveryCapsule(BackupModel):
    format_version: str = FORMAT_VERSION
    kdf: str = "Argon2id"
    memory_kib: int = 65_536
    iterations: int = 3
    parallelism: int = 1
    salt: str
    nonce: str
    ciphertext: str


class BackupCrypto:
    """Local-only encryption, signing, and recovery operations."""

    @staticmethod
    def generate_scope_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def derive_domain_key(
        root_key: bytes,
        *,
        scope_kind: ScopeKind,
        scope_id: str,
        key_epoch: int,
    ) -> bytes:
        if len(root_key) < 32:
            raise ValueError("root keys must contain at least 256 bits")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=(
                f"{FORMAT_VERSION}:{scope_kind.value}:{scope_id}:epoch:{key_epoch}"
            ).encode("utf-8"),
        ).derive(root_key)

    @staticmethod
    def opaque_scope_id(scope_key: bytes, scope_id: str) -> str:
        digest = hmac.new(
            scope_key,
            f"{FORMAT_VERSION}:scope:{scope_id}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return _b64(digest[:20])

    @staticmethod
    def encrypt_chunk(
        plaintext: bytes,
        *,
        scope_key: bytes,
        opaque_scope_id: str,
        key_epoch: int,
    ) -> EncryptedChunk:
        plaintext_digest = hashlib.sha256(plaintext).digest()
        index_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"{FORMAT_VERSION}:chunk-index".encode(),
        ).derive(scope_key)
        object_id = _b64(hmac.new(index_key, plaintext_digest, hashlib.sha256).digest())
        aad = f"{FORMAT_VERSION}:chunk:{opaque_scope_id}:{object_id}".encode()
        data_key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(scope_key).encrypt(wrap_nonce, data_key, aad)
        return EncryptedChunk(
            object_id=object_id,
            nonce=_b64(nonce),
            ciphertext=_b64(ciphertext),
            wrapped_data_key=WrappedKeyReference(
                key_epoch=key_epoch,
                nonce=_b64(wrap_nonce),
                ciphertext=_b64(wrapped),
            ),
        )

    @staticmethod
    def decrypt_chunk(
        chunk: EncryptedChunk,
        *,
        scope_key: bytes,
        opaque_scope_id: str,
    ) -> bytes:
        aad = (
            f"{FORMAT_VERSION}:chunk:{opaque_scope_id}:{chunk.object_id}".encode()
        )
        data_key = AESGCM(scope_key).decrypt(
            _unb64(chunk.wrapped_data_key.nonce),
            _unb64(chunk.wrapped_data_key.ciphertext),
            aad,
        )
        return AESGCM(data_key).decrypt(
            _unb64(chunk.nonce),
            _unb64(chunk.ciphertext),
            aad,
        )

    @staticmethod
    def generate_signing_key() -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    @staticmethod
    def private_key_bytes(key: Ed25519PrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def public_key_bytes(key: Ed25519PublicKey) -> bytes:
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def signer_fingerprint(public_key: bytes) -> str:
        return hashlib.sha256(public_key).hexdigest()

    @staticmethod
    def encrypt_and_sign_manifest(
        manifest: BackupManifest,
        *,
        scope_key: bytes,
        signing_key: Ed25519PrivateKey,
    ) -> SignedManifestEnvelope:
        nonce = os.urandom(12)
        aad = (
            f"{FORMAT_VERSION}:manifest:{manifest.opaque_scope_id}:"
            f"{manifest.lineage.sequence}:{manifest.key_epoch}"
        ).encode()
        ciphertext = AESGCM(scope_key).encrypt(
            nonce,
            canonical_json(manifest),
            aad,
        )
        public_key = BackupCrypto.public_key_bytes(signing_key.public_key())
        unsigned = SignedManifestEnvelope(
            opaque_scope_id=manifest.opaque_scope_id,
            sequence=manifest.lineage.sequence,
            key_epoch=manifest.key_epoch,
            nonce=_b64(nonce),
            ciphertext=_b64(ciphertext),
            signer_public_key=_b64(public_key),
            signature="pending",
            manifest_digest="pending",
        )
        signature = signing_key.sign(unsigned.signing_payload())
        digest = hashlib.sha256(unsigned.signing_payload() + signature).hexdigest()
        return unsigned.model_copy(
            update={"signature": _b64(signature), "manifest_digest": digest}
        )

    @staticmethod
    def verify_and_decrypt_manifest(
        envelope: SignedManifestEnvelope,
        *,
        scope_key: bytes,
        trusted_public_key: bytes,
    ) -> BackupManifest:
        if not hmac.compare_digest(
            envelope.signer_public_key,
            _b64(trusted_public_key),
        ):
            raise ValueError("manifest signer is not trusted")
        try:
            Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
                _unb64(envelope.signature),
                envelope.signing_payload(),
            )
        except InvalidSignature as exc:
            raise ValueError("manifest signature is invalid") from exc
        digest = hashlib.sha256(
            envelope.signing_payload() + _unb64(envelope.signature)
        ).hexdigest()
        if not hmac.compare_digest(digest, envelope.manifest_digest):
            raise ValueError("manifest digest is invalid")
        aad = (
            f"{FORMAT_VERSION}:manifest:{envelope.opaque_scope_id}:"
            f"{envelope.sequence}:{envelope.key_epoch}"
        ).encode()
        plaintext = AESGCM(scope_key).decrypt(
            _unb64(envelope.nonce),
            _unb64(envelope.ciphertext),
            aad,
        )
        manifest = BackupManifest.model_validate_json(plaintext)
        if (
            manifest.opaque_scope_id != envelope.opaque_scope_id
            or manifest.lineage.sequence != envelope.sequence
            or manifest.key_epoch != envelope.key_epoch
        ):
            raise ValueError("manifest envelope metadata does not match plaintext")
        return manifest

    @staticmethod
    def checkpoint(
        envelope: SignedManifestEnvelope,
        *,
        witnessed_at: datetime | None = None,
    ) -> ManifestCheckpoint:
        public_key = _unb64(envelope.signer_public_key)
        return ManifestCheckpoint(
            opaque_scope_id=envelope.opaque_scope_id,
            sequence=envelope.sequence,
            manifest_digest=envelope.manifest_digest,
            signer_fingerprint=BackupCrypto.signer_fingerprint(public_key),
            witnessed_at=witnessed_at or _utcnow(),
        )

    @staticmethod
    def verify_checkpoint(
        envelope: SignedManifestEnvelope,
        checkpoint: ManifestCheckpoint,
    ) -> None:
        if checkpoint.opaque_scope_id != envelope.opaque_scope_id:
            raise ValueError("checkpoint scope does not match")
        if envelope.sequence < checkpoint.sequence:
            raise ValueError("backup provider attempted manifest rollback")
        if envelope.sequence == checkpoint.sequence and not hmac.compare_digest(
            envelope.manifest_digest,
            checkpoint.manifest_digest,
        ):
            raise ValueError("backup provider supplied a forked manifest")
        fingerprint = BackupCrypto.signer_fingerprint(
            _unb64(envelope.signer_public_key)
        )
        if not hmac.compare_digest(fingerprint, checkpoint.signer_fingerprint):
            raise ValueError("manifest signer changed without authorization")

    @staticmethod
    def generate_recovery_code() -> str:
        payload = base64.b32encode(os.urandom(32)).decode("ascii").rstrip("=")
        checksum = base64.b32encode(
            hashlib.sha256(payload.encode("ascii")).digest()[:4]
        ).decode("ascii").rstrip("=")
        grouped = "-".join(
            (payload + checksum)[offset : offset + 4]
            for offset in range(0, len(payload + checksum), 4)
        )
        return f"{_RECOVERY_PREFIX}-{grouped}"

    @staticmethod
    def _normalize_recovery_code(code: str) -> bytes:
        normalized = re.sub(r"[\s-]", "", code.upper())
        if not normalized.startswith(_RECOVERY_PREFIX):
            raise ValueError("recovery code prefix is invalid")
        encoded = normalized[len(_RECOVERY_PREFIX) :]
        if not _CODE_RE.fullmatch(encoded) or len(encoded) < 16:
            raise ValueError("recovery code format is invalid")
        payload, checksum = encoded[:-7], encoded[-7:]
        expected = base64.b32encode(
            hashlib.sha256(payload.encode("ascii")).digest()[:4]
        ).decode("ascii").rstrip("=")
        if not hmac.compare_digest(checksum, expected):
            raise ValueError("recovery code checksum is invalid")
        return payload.encode("ascii")

    @staticmethod
    def seal_recovery_capsule(
        payload: bytes,
        recovery_code: str,
    ) -> RecoveryCapsule:
        secret = BackupCrypto._normalize_recovery_code(recovery_code)
        salt = os.urandom(16)
        key = hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=3,
            memory_cost=65_536,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            payload,
            f"{FORMAT_VERSION}:recovery-capsule".encode(),
        )
        return RecoveryCapsule(
            salt=_b64(salt),
            nonce=_b64(nonce),
            ciphertext=_b64(ciphertext),
        )

    @staticmethod
    def open_recovery_capsule(
        capsule: RecoveryCapsule,
        recovery_code: str,
    ) -> bytes:
        secret = BackupCrypto._normalize_recovery_code(recovery_code)
        key = hash_secret_raw(
            secret=secret,
            salt=_unb64(capsule.salt),
            time_cost=capsule.iterations,
            memory_cost=capsule.memory_kib,
            parallelism=capsule.parallelism,
            hash_len=32,
            type=Type.ID,
        )
        return AESGCM(key).decrypt(
            _unb64(capsule.nonce),
            _unb64(capsule.ciphertext),
            f"{FORMAT_VERSION}:recovery-capsule".encode(),
        )


__all__ = [
    "FORMAT_VERSION",
    "BackendCapabilities",
    "BackupCrypto",
    "BackupManifest",
    "ChunkReference",
    "EncryptedChunk",
    "ManifestCheckpoint",
    "RecoveryCapsule",
    "RestorePlan",
    "RestoreStatus",
    "ScopeKind",
    "SignedManifestEnvelope",
    "SnapshotLineage",
    "Tombstone",
    "VerificationRecord",
    "VerificationStatus",
    "WrappedKeyReference",
    "canonical_json",
]
