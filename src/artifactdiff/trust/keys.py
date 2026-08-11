"""Encrypted local Ed25519 private-key storage."""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from artifactdiff.errors import SignatureError
from artifactdiff.trust.models import SecretProvider


def _secret(provider: SecretProvider, identity: str) -> bytes:
    try:
        value = provider.get_secret(identity)
    except Exception:  # noqa: BLE001 - provider errors may contain secret material
        raise SignatureError("private-key secret provider failed") from None
    if not isinstance(value, bytes) or not value:
        raise SignatureError("private-key secret must be non-empty bytes")
    return value


def _public_key_fingerprint(private_key: Ed25519PrivateKey) -> str:
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()


def _atomic_private_write(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        raise SignatureError("could not write encrypted private key") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def generate_private_key(
    path: Path,
    *,
    identity: str,
    secret_provider: SecretProvider,
) -> str:
    """Generate and atomically store one encrypted PKCS#8 Ed25519 key."""
    secret = _secret(secret_provider, identity)
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(secret),
    )
    _atomic_private_write(path, private_bytes)
    return _public_key_fingerprint(private_key)


def load_private_key(
    path: Path,
    *,
    identity: str,
    secret_provider: SecretProvider,
) -> Ed25519PrivateKey:
    """Load one encrypted PKCS#8 Ed25519 key with sanitized failures."""
    secret = _secret(secret_provider, identity)
    try:
        payload = path.read_bytes()
        private_key = serialization.load_pem_private_key(payload, password=secret)
    except (OSError, TypeError, UnsupportedAlgorithm, ValueError):
        raise SignatureError("could not load encrypted private key") from None
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignatureError("encrypted private key is not Ed25519")
    return private_key
