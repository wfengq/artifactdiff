from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from artifactdiff.errors import SignatureError
from artifactdiff.trust import generate_private_key, load_private_key


class FixedSecretProvider:
    def __init__(self, secret: bytes = b"correct horse battery staple") -> None:
        self.secret = secret
        self.identities: list[str] = []

    def get_secret(self, identity: str) -> bytes:
        self.identities.append(identity)
        return self.secret


def test_private_key_is_encrypted_pkcs8_and_loadable(tmp_path: Path) -> None:
    path = tmp_path / "alice.pem"
    secrets = FixedSecretProvider()

    fingerprint = generate_private_key(path, identity="alice", secret_provider=secrets)

    raw = path.read_bytes()
    assert raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert b"-----BEGIN PRIVATE KEY-----" not in raw
    assert len(fingerprint) == 64
    assert set(fingerprint) <= set("0123456789abcdef")
    assert isinstance(
        load_private_key(path, identity="alice", secret_provider=secrets),
        Ed25519PrivateKey,
    )
    assert secrets.identities == ["alice", "alice"]
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_empty_key_secret_fails_without_leaving_a_file(tmp_path: Path) -> None:
    path = tmp_path / "alice.pem"

    with pytest.raises(SignatureError, match="non-empty"):
        generate_private_key(path, identity="alice", secret_provider=FixedSecretProvider(b""))

    assert not path.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_wrong_passphrase_is_sanitized(tmp_path: Path) -> None:
    path = tmp_path / "alice.pem"
    generate_private_key(path, identity="alice", secret_provider=FixedSecretProvider())

    with pytest.raises(SignatureError) as caught:
        load_private_key(
            path,
            identity="alice",
            secret_provider=FixedSecretProvider(b"TOP_SECRET_BAD_PASSPHRASE"),
        )

    message = str(caught.value)
    assert "TOP_SECRET" not in message
    assert "PRIVATE KEY" not in message


def test_invalid_key_file_is_sanitized(tmp_path: Path) -> None:
    path = tmp_path / "alice.pem"
    path.write_text("TOP_SECRET_INVALID_KEY", encoding="utf-8")

    with pytest.raises(SignatureError) as caught:
        load_private_key(path, identity="alice", secret_provider=FixedSecretProvider())

    assert "TOP_SECRET" not in str(caught.value)


def test_atomic_replace_failure_preserves_existing_key_and_cleans_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "alice.pem"
    path.write_bytes(b"EXISTING_ENCRYPTED_KEY")

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError(f"replace failed: {source} -> {destination}")

    monkeypatch.setattr("artifactdiff.trust.keys.os.replace", fail_replace)

    with pytest.raises(SignatureError):
        generate_private_key(path, identity="alice", secret_provider=FixedSecretProvider())

    assert path.read_bytes() == b"EXISTING_ENCRYPTED_KEY"
    assert not list(tmp_path.glob("*.tmp"))
