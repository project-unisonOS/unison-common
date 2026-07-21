import pytest
from cryptography.fernet import InvalidToken

from unison_common.trust import LocalDevelopmentKeyBroker, read_secret_setting


def test_per_person_key_handles_cannot_decrypt_each_other():
    broker = LocalDevelopmentKeyBroker(b"local-development-root-secret-32-bytes-minimum")
    ciphertext = broker.encrypt(
        key_handle="key-alice",
        plaintext=b"alice-private-canary",
        associated_data=b"profile",
    )
    assert b"alice-private-canary" not in ciphertext
    assert broker.decrypt(
        key_handle="key-alice",
        ciphertext=ciphertext,
        associated_data=b"profile",
    ) == b"alice-private-canary"
    with pytest.raises(InvalidToken):
        broker.decrypt(
            key_handle="key-bob",
            ciphertext=ciphertext,
            associated_data=b"profile",
        )


def test_resource_class_is_bound_as_associated_data():
    broker = LocalDevelopmentKeyBroker(b"another-local-development-root-secret-value")
    ciphertext = broker.encrypt(key_handle="key-alice", plaintext=b"secret", associated_data=b"vault")
    with pytest.raises(InvalidToken):
        broker.decrypt(key_handle="key-alice", ciphertext=ciphertext, associated_data=b"profile")


def test_secret_file_takes_precedence_over_legacy_environment(tmp_path, monkeypatch):
    secret_file = tmp_path / "root-key"
    secret_file.write_text("file-secret\n", encoding="utf-8")
    monkeypatch.setenv("EXAMPLE_SECRET", "environment-secret")
    monkeypatch.setenv("EXAMPLE_SECRET_FILE", str(secret_file))
    assert read_secret_setting("EXAMPLE_SECRET") == "file-secret"
