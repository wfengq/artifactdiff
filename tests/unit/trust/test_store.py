from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from artifactdiff.errors import SignatureError
from artifactdiff.trust import (
    TrustIdentity,
    TrustRole,
    TrustStore,
    resolve_identity,
)


def _identity(identity: str = "alice") -> TrustIdentity:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
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
        roles=frozenset({TrustRole.POLICY_AUTHORIZER}),
    )


def test_store_resolves_exact_identity_and_fingerprint() -> None:
    identity = _identity()
    store = TrustStore(identities=[identity])

    assert (
        resolve_identity(
            store,
            identity="alice",
            fingerprint=identity.public_key_fingerprint,
        )
        == identity
    )


def test_store_rejects_duplicate_identity_ids_and_fingerprints() -> None:
    alice = _identity("alice")

    with pytest.raises(ValidationError):
        TrustStore(identities=[alice, alice.model_copy()])
    with pytest.raises(ValidationError):
        TrustStore(identities=[alice, alice.model_copy(update={"id": "bob"})])


@pytest.mark.parametrize(
    ("identity", "fingerprint"),
    [
        ("bob", None),
        ("alice", "b" * 64),
    ],
)
def test_store_lookup_mismatch_fails_closed(
    identity: str,
    fingerprint: str | None,
) -> None:
    alice = _identity()

    with pytest.raises(SignatureError):
        resolve_identity(
            TrustStore(identities=[alice]),
            identity=identity,
            fingerprint=fingerprint or alice.public_key_fingerprint,
        )


def test_identity_rejects_empty_roles_and_unknown_fields() -> None:
    identity = _identity()

    with pytest.raises(ValidationError):
        TrustIdentity.model_validate({**identity.model_dump(), "roles": []})
    with pytest.raises(ValidationError):
        TrustIdentity.model_validate({**identity.model_dump(), "private_key": "TOP_SECRET"})


def test_store_revalidates_prebuilt_identity_instances() -> None:
    identity = _identity()
    identity.public_key_fingerprint = "invalid"

    with pytest.raises(ValidationError):
        TrustStore(identities=[identity])


def test_public_lookup_revalidates_a_mutated_store() -> None:
    store = TrustStore(identities=[_identity()])
    store.identities[0].public_key_fingerprint = "invalid"

    with pytest.raises(SignatureError):
        resolve_identity(store, identity="alice", fingerprint="invalid")


@pytest.mark.parametrize(
    "update",
    [
        {"revoked": 1},
        {"id": b"alice"},
        {"roles": ["policy_authorizer"]},
    ],
    ids=["boolean", "identity", "role"],
)
def test_identity_rejects_python_scalar_coercion(update: dict[str, object]) -> None:
    identity = _identity()

    with pytest.raises(ValidationError):
        TrustIdentity.model_validate({**identity.model_dump(), **update})
