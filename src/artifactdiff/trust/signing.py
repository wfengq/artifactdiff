"""Domain-separated Ed25519 signing and trust verification."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import JsonValue, ValidationError

from artifactdiff.errors import SignatureError
from artifactdiff.trust.keys import load_private_key
from artifactdiff.trust.models import (
    SecretProvider,
    SignatureEnvelope,
    SignatureInspection,
    TrustIdentity,
    TrustRole,
    TrustStore,
)
from artifactdiff.trust.store import resolve_identity

_PURPOSE = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DOMAIN = b"ArtifactDiff-Signature-v1\0"


def _signature_message(purpose: str, digest: str) -> bytes:
    if not isinstance(purpose, str) or _PURPOSE.fullmatch(purpose) is None:
        raise SignatureError("invalid signature purpose")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise SignatureError("invalid canonical object digest")
    return _DOMAIN + purpose.encode("ascii") + b"\0" + bytes.fromhex(digest)


def _public_key(identity: TrustIdentity) -> Ed25519PublicKey:
    try:
        loaded = serialization.load_pem_public_key(identity.public_key_pem.encode("ascii"))
    except (TypeError, UnsupportedAlgorithm, ValueError, UnicodeEncodeError):
        raise SignatureError("trusted public key is invalid") from None
    if not isinstance(loaded, Ed25519PublicKey):
        raise SignatureError("trusted public key is not Ed25519")
    public_der = loaded.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if hashlib.sha256(public_der).hexdigest() != identity.public_key_fingerprint:
        raise SignatureError("trusted public key fingerprint is invalid")
    return loaded


def _private_matches_identity(
    private_key: Ed25519PrivateKey,
    identity: TrustIdentity,
) -> None:
    expected = _public_key(identity).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    observed = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if observed != expected:
        raise SignatureError("private key does not match trust identity")


def _currently_trusted(
    identity: TrustIdentity,
    *,
    required_role: TrustRole | None,
    now: datetime,
) -> bool:
    if identity.revoked:
        return False
    if required_role is not None and required_role not in identity.roles:
        return False
    if identity.valid_from is not None and now < identity.valid_from:
        return False
    return identity.valid_until is None or now <= identity.valid_until


def sign_digest(
    private_key: Ed25519PrivateKey,
    *,
    identity: TrustIdentity,
    purpose: str,
    digest: str,
    claimed_time: datetime | None = None,
    trusted_time: dict[str, JsonValue] | None = None,
) -> SignatureEnvelope:
    """Sign exactly one purpose-separated canonical SHA-256 digest."""
    try:
        checked_identity = TrustIdentity.model_validate(identity)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SignatureError("invalid signing identity") from None
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignatureError("signing key is not Ed25519")
    message = _signature_message(purpose, digest)
    _private_matches_identity(private_key, checked_identity)
    signature = private_key.sign(message)
    try:
        return SignatureEnvelope(
            public_key_fingerprint=checked_identity.public_key_fingerprint,
            identity=checked_identity.id,
            purpose=purpose,
            canonical_object_sha256=digest,
            claimed_signing_time=claimed_time,
            trusted_time_evidence=trusted_time,
            signature_base64=base64.b64encode(signature).decode("ascii"),
        )
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SignatureError("invalid signature metadata") from None


def inspect_signature(
    envelope: SignatureEnvelope,
    *,
    purpose: str,
    digest: str,
    trust_store: TrustStore,
    required_role: TrustRole | None = None,
    now: datetime | None = None,
) -> SignatureInspection:
    """Report cryptographic validity separately from current trust."""
    try:
        checked_envelope = SignatureEnvelope.model_validate(envelope)
        checked_store = TrustStore.model_validate(trust_store)
        message = _signature_message(purpose, digest)
        if checked_envelope.purpose != purpose:
            raise SignatureError("signature purpose does not match")
        if checked_envelope.canonical_object_sha256 != digest:
            raise SignatureError("signature digest does not match")
        identity = resolve_identity(
            checked_store,
            identity=checked_envelope.identity,
            fingerprint=checked_envelope.public_key_fingerprint,
        )
        public_key = _public_key(identity)
        signature = base64.b64decode(checked_envelope.signature_base64, validate=True)
        public_key.verify(signature, message)
    except (
        InvalidSignature,
        SignatureError,
        ValidationError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return SignatureInspection(
            signature_valid=False,
            currently_trusted=False,
            errors=["signature_invalid"],
        )

    checked_now = now or datetime.now(UTC)
    if checked_now.tzinfo is None or checked_now.utcoffset() is None:
        return SignatureInspection(
            signature_valid=True,
            currently_trusted=False,
            identity=identity,
            errors=["verification_time_invalid"],
        )
    trusted = _currently_trusted(identity, required_role=required_role, now=checked_now)
    return SignatureInspection(
        signature_valid=True,
        currently_trusted=trusted,
        identity=identity,
        errors=[] if trusted else ["identity_not_currently_trusted"],
    )


def verify_signature(
    envelope: SignatureEnvelope,
    *,
    purpose: str,
    digest: str,
    required_role: TrustRole,
    trust_store: TrustStore,
    now: datetime | None = None,
) -> TrustIdentity:
    """Require a valid signature from a currently trusted role holder."""
    inspection = inspect_signature(
        envelope,
        purpose=purpose,
        digest=digest,
        required_role=required_role,
        trust_store=trust_store,
        now=now,
    )
    if not inspection.signature_valid:
        raise SignatureError("signature verification failed")
    if not inspection.currently_trusted or inspection.identity is None:
        raise SignatureError("signing identity is not currently trusted")
    return inspection.identity


@dataclass(frozen=True, slots=True)
class LocalEd25519SigningProvider:
    """Load a local encrypted key only after public authorization checks."""

    identity: str
    private_key_path: Path
    secret_provider: SecretProvider
    trust_store: TrustStore

    def sign(
        self,
        *,
        purpose: str,
        digest: str,
        required_role: TrustRole,
    ) -> SignatureEnvelope:
        try:
            store = TrustStore.model_validate(self.trust_store)
        except (ValidationError, RecursionError, TypeError, ValueError):
            raise SignatureError("invalid trust store") from None
        matches = [item for item in store.identities if item.id == self.identity]
        if len(matches) != 1:
            raise SignatureError("signing identity is not trusted")
        identity = matches[0]
        if not _currently_trusted(
            identity,
            required_role=required_role,
            now=datetime.now(UTC),
        ):
            raise SignatureError("signing identity lacks the required current role")
        _signature_message(purpose, digest)
        _public_key(identity)
        private_key = load_private_key(
            self.private_key_path,
            identity=identity.id,
            secret_provider=self.secret_provider,
        )
        return sign_digest(
            private_key,
            identity=identity,
            purpose=purpose,
            digest=digest,
        )
