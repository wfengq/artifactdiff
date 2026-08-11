"""Verified policy authorization and controlled edit-session API."""

from artifactdiff.session.models import EditSession, SealedPolicyArtifact, SessionOpenedEvent
from artifactdiff.session.service import (
    authorize_policy,
    claim_verified_candidate,
    load_edit_session,
    load_sealed_policy,
    open_verified_edit_session,
    write_sealed_policy,
)

__all__ = [
    "EditSession",
    "SealedPolicyArtifact",
    "SessionOpenedEvent",
    "authorize_policy",
    "claim_verified_candidate",
    "load_edit_session",
    "load_sealed_policy",
    "open_verified_edit_session",
    "write_sealed_policy",
]
