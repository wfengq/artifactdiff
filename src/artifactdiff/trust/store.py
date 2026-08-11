"""Fail-closed trust-store lookup."""

from pydantic import ValidationError

from artifactdiff.errors import SignatureError
from artifactdiff.trust.models import TrustIdentity, TrustStore


def resolve_identity(
    trust_store: TrustStore,
    *,
    identity: str,
    fingerprint: str,
) -> TrustIdentity:
    """Resolve exactly one identity and require its bound key fingerprint."""
    try:
        checked_store = TrustStore.model_validate(trust_store)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SignatureError("trust store is invalid") from None
    matches = [item for item in checked_store.identities if item.id == identity]
    if len(matches) != 1:
        raise SignatureError("signature identity is not trusted")
    resolved = matches[0]
    if resolved.public_key_fingerprint != fingerprint:
        raise SignatureError("signature key fingerprint is not trusted")
    return resolved
