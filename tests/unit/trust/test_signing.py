from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from artifactdiff.errors import SignatureError
from artifactdiff.trust import (
    LocalEd25519SigningProvider,
    SignatureEnvelope,
    TrustIdentity,
    TrustRole,
    TrustStore,
    generate_private_key,
    inspect_signature,
    load_private_key,
    sign_digest,
    verify_signature,
)

_RFC_8032_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_EXPECTED_SIGNATURE = (
    "2Xs1gEfZWdQF5AIzX0tJW8NsR4yDw+/meYhL1XFcBB1/lpkrlWJ8yhMRfKNAWeUsfpYdnIru8VT9TmhDBVmpCQ=="
)


def _identity(
    private_key: Ed25519PrivateKey,
    *,
    identity: str = "alice",
    roles: frozenset[TrustRole] = frozenset(TrustRole),
    revoked: bool = False,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
) -> TrustIdentity:
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return TrustIdentity(
        id=identity,
        subject_type="human",
        public_key_fingerprint=hashlib.sha256(public_der).hexdigest(),
        public_key_pem=public_pem,
        roles=roles,
        revoked=revoked,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_RFC_8032_SEED)


class RecordingSecretProvider:
    def __init__(self, secret: bytes) -> None:
        self.secret = secret
        self.calls: list[str] = []

    def get_secret(self, identity: str) -> bytes:
        self.calls.append(identity)
        return self.secret


def test_fixed_vector_binds_domain_purpose_and_digest() -> None:
    private_key = _private_key()
    identity = _identity(private_key)

    envelope = sign_digest(
        private_key,
        identity=identity,
        purpose="policy_authorization",
        digest="a" * 64,
    )

    assert envelope.signature_base64 == _EXPECTED_SIGNATURE
    assert (
        verify_signature(
            envelope,
            purpose="policy_authorization",
            digest="a" * 64,
            required_role=TrustRole.POLICY_AUTHORIZER,
            trust_store=TrustStore(identities=[identity]),
        )
        == identity
    )


@pytest.mark.parametrize(
    ("purpose", "digest", "role"),
    [
        ("finding_approval", "a" * 64, TrustRole.FINDING_APPROVER),
        ("policy_authorization", "b" * 64, TrustRole.POLICY_AUTHORIZER),
        ("policy_authorization", "a" * 64, TrustRole.ARCHIVE_SIGNER),
    ],
    ids=["purpose", "digest", "role"],
)
def test_signature_rejects_substitution_and_role_mismatch(
    purpose: str,
    digest: str,
    role: TrustRole,
) -> None:
    private_key = _private_key()
    identity = _identity(
        private_key,
        roles=frozenset({TrustRole.POLICY_AUTHORIZER}),
    )
    envelope = sign_digest(
        private_key,
        identity=identity,
        purpose="policy_authorization",
        digest="a" * 64,
    )

    with pytest.raises(SignatureError):
        verify_signature(
            envelope,
            purpose=purpose,
            digest=digest,
            required_role=role,
            trust_store=TrustStore(identities=[identity]),
        )


def test_signature_tamper_is_rejected() -> None:
    private_key = _private_key()
    identity = _identity(private_key)
    envelope = sign_digest(
        private_key,
        identity=identity,
        purpose="policy_authorization",
        digest="a" * 64,
    )
    signature = bytearray(base64.b64decode(envelope.signature_base64))
    signature[0] ^= 1
    tampered = envelope.model_copy(
        update={"signature_base64": base64.b64encode(signature).decode("ascii")}
    )

    with pytest.raises(SignatureError):
        verify_signature(
            tampered,
            purpose="policy_authorization",
            digest="a" * 64,
            required_role=TrustRole.POLICY_AUTHORIZER,
            trust_store=TrustStore(identities=[identity]),
        )


def test_revoked_identity_preserves_historical_signature_status() -> None:
    private_key = _private_key()
    active = _identity(private_key)
    revoked = active.model_copy(update={"revoked": True})
    envelope = sign_digest(
        private_key,
        identity=active,
        purpose="policy_authorization",
        digest="a" * 64,
    )

    inspection = inspect_signature(
        envelope,
        purpose="policy_authorization",
        digest="a" * 64,
        trust_store=TrustStore(identities=[revoked]),
    )

    assert inspection.signature_valid is True
    assert inspection.currently_trusted is False
    assert inspection.identity == revoked


def test_claimed_time_does_not_override_current_validity() -> None:
    private_key = _private_key()
    now = datetime.now(UTC)
    expired = _identity(private_key, valid_until=now - timedelta(days=1))
    envelope = sign_digest(
        private_key,
        identity=expired,
        purpose="policy_authorization",
        digest="a" * 64,
        claimed_time=now - timedelta(days=2),
    )

    inspection = inspect_signature(
        envelope,
        purpose="policy_authorization",
        digest="a" * 64,
        trust_store=TrustStore(identities=[expired]),
        now=now,
    )

    assert inspection.signature_valid is True
    assert inspection.currently_trusted is False
    with pytest.raises(SignatureError):
        verify_signature(
            envelope,
            purpose="policy_authorization",
            digest="a" * 64,
            required_role=TrustRole.POLICY_AUTHORIZER,
            trust_store=TrustStore(identities=[expired]),
            now=now,
        )


@pytest.mark.parametrize(
    ("purpose", "digest"),
    [
        ("Policy", "a" * 64),
        ("policy authorization", "a" * 64),
        ("policy", "A" * 64),
        ("policy", "not-a-digest"),
    ],
)
def test_signing_rejects_noncanonical_domain_inputs(purpose: str, digest: str) -> None:
    private_key = _private_key()

    with pytest.raises(SignatureError):
        sign_digest(
            private_key,
            identity=_identity(private_key),
            purpose=purpose,
            digest=digest,
        )


def test_signature_envelope_rejects_noncanonical_base64() -> None:
    private_key = _private_key()
    envelope = sign_digest(
        private_key,
        identity=_identity(private_key),
        purpose="policy_authorization",
        digest="a" * 64,
    )

    with pytest.raises(ValueError):
        SignatureEnvelope.model_validate(
            {**envelope.model_dump(), "signature_base64": envelope.signature_base64 + "\n"}
        )


def test_local_provider_checks_role_before_loading_private_key(tmp_path: Path) -> None:
    private_key = _private_key()
    identity = _identity(
        private_key,
        roles=frozenset({TrustRole.POLICY_AUTHORIZER}),
    )
    secrets = RecordingSecretProvider(b"unused")
    provider = LocalEd25519SigningProvider(
        identity="alice",
        private_key_path=tmp_path / "missing.pem",
        secret_provider=secrets,
        trust_store=TrustStore(identities=[identity]),
    )

    with pytest.raises(SignatureError):
        provider.sign(
            purpose="bundle_manifest",
            digest="a" * 64,
            required_role=TrustRole.ARCHIVE_SIGNER,
        )

    assert secrets.calls == []


def test_local_provider_checks_public_identity_before_loading_private_key(tmp_path: Path) -> None:
    identity = _identity(_private_key()).model_copy(
        update={"public_key_pem": "TOP_SECRET_INVALID_PUBLIC_KEY"}
    )
    secrets = RecordingSecretProvider(b"unused")
    provider = LocalEd25519SigningProvider(
        identity="alice",
        private_key_path=tmp_path / "missing.pem",
        secret_provider=secrets,
        trust_store=TrustStore(identities=[identity]),
    )

    with pytest.raises(SignatureError) as caught:
        provider.sign(
            purpose="policy_authorization",
            digest="a" * 64,
            required_role=TrustRole.POLICY_AUTHORIZER,
        )

    assert secrets.calls == []
    assert "TOP_SECRET" not in str(caught.value)


def test_local_provider_signs_with_the_trusted_encrypted_key(tmp_path: Path) -> None:
    path = tmp_path / "alice.pem"
    secrets = RecordingSecretProvider(b"correct horse battery staple")
    fingerprint = generate_private_key(path, identity="alice", secret_provider=secrets)
    private_key = load_private_key(path, identity="alice", secret_provider=secrets)
    identity = _identity(private_key)
    assert identity.public_key_fingerprint == fingerprint
    secrets.calls.clear()
    store = TrustStore(identities=[identity])
    provider = LocalEd25519SigningProvider(
        identity="alice",
        private_key_path=path,
        secret_provider=secrets,
        trust_store=store,
    )

    envelope = provider.sign(
        purpose="policy_authorization",
        digest="a" * 64,
        required_role=TrustRole.POLICY_AUTHORIZER,
    )

    assert secrets.calls == ["alice"]
    assert (
        verify_signature(
            envelope,
            purpose="policy_authorization",
            digest="a" * 64,
            required_role=TrustRole.POLICY_AUTHORIZER,
            trust_store=store,
        )
        == identity
    )
