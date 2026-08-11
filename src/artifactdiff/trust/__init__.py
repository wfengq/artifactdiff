"""Offline trust primitives for ArtifactDiff authorization."""

from artifactdiff.trust.keys import generate_private_key, load_private_key
from artifactdiff.trust.models import (
    PolicyAuthorization,
    SecretProvider,
    SignatureEnvelope,
    SignatureInspection,
    SigningProvider,
    TrustIdentity,
    TrustRole,
    TrustStore,
)
from artifactdiff.trust.signing import (
    LocalEd25519SigningProvider,
    inspect_signature,
    sign_digest,
    verify_signature,
)
from artifactdiff.trust.store import resolve_identity

__all__ = [
    "LocalEd25519SigningProvider",
    "PolicyAuthorization",
    "SecretProvider",
    "SignatureEnvelope",
    "SignatureInspection",
    "SigningProvider",
    "TrustIdentity",
    "TrustRole",
    "TrustStore",
    "generate_private_key",
    "inspect_signature",
    "load_private_key",
    "resolve_identity",
    "sign_digest",
    "verify_signature",
]
