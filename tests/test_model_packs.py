from __future__ import annotations

import json
import tarfile
from pathlib import Path

from unison_common.models import ModelPackResolver


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def test_model_pack_install_verify_and_lookup(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    payload_file = pack_root / "faster-whisper" / "tiny.en" / "model.bin"
    payload_file.parent.mkdir(parents=True, exist_ok=True)
    payload_file.write_bytes(b"dummy-weights")

    manifest = {
        "schema_version": "unison.modelpack.manifest.v1",
        "pack": {"id": "test.core", "version": "0.0.1"},
        "compat": {"os": [], "arch": [], "gpu": "optional"},
        "models": [
            {
                "model_id": "asr:faster-whisper:tiny.en",
                "engine": "faster-whisper",
                "role": "asr.fast",
                "install_relpath": "faster-whisper/tiny.en",
                "required": True,
            }
        ],
        "files": [
            {
                "path": "faster-whisper/tiny.en/model.bin",
                "sha256": _sha256(payload_file),
                "size_bytes": payload_file.stat().st_size,
                "model_ids": ["asr:faster-whisper:tiny.en"],
            }
        ],
    }
    (pack_root / "models.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    pack_tgz = tmp_path / "test.core-0.0.1.tgz"
    with tarfile.open(pack_tgz, "w:gz") as tf:
        for path in pack_root.rglob("*"):
            tf.add(path, arcname=str(path.relative_to(pack_root)))

    base_dir = tmp_path / "models"
    resolver = ModelPackResolver(base_dir=base_dir)
    ref = resolver.install_from_path(pack_path=str(pack_tgz))

    assert ref.pack_id == "test.core"
    assert ref.pack_version == "0.0.1"

    verify = resolver.verify_pack(ref=ref)
    assert verify.ok, (verify.missing, verify.invalid)

    model_path = resolver.get_model_path(model_id="asr:faster-whisper:tiny.en")
    assert model_path == (base_dir / "faster-whisper" / "tiny.en").resolve()
    assert (model_path / "model.bin").exists()

