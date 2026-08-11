"""Strict models for authorized ArtifactDiff edit sessions."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from artifactdiff.models import StrictModel
from artifactdiff.policy import FrozenPolicy
from artifactdiff.trust import PolicyAuthorization, SignatureEnvelope

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class SessionModel(StrictModel):
    """Session model that rejects extras and revalidates nested instances."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always", strict=True)


class SealedPolicyArtifact(SessionModel):
    schema_version: Literal["1.0"] = "1.0"
    frozen: FrozenPolicy
    authorization: PolicyAuthorization | None = None


class SessionOpenedEvent(SessionModel):
    schema_version: Literal["1.0"] = "1.0"
    event_type: Literal["session_opened"] = "session_opened"
    sequence: StrictInt = Field(default=1, ge=1, le=1)
    session_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    frozen_policy_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    baseline_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_authorization_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    previous_event_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    nonce_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    chronology: Literal["artifactdiff_controlled_session"] = "artifactdiff_controlled_session"
    trusted_time: StrictBool = False
    signature: SignatureEnvelope


class EditSession(SessionModel):
    schema_version: Literal["1.0"] = "1.0"
    assurance: Literal["verified"] = "verified"
    session_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    root_path: Path
    policy_path: Path
    baseline_snapshot_path: Path
    candidate_path: Path
    frozen_policy_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    baseline_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_authorization_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    events: list[SessionOpenedEvent] = Field(min_length=1, max_length=1)

    @model_validator(mode="after")
    def event_matches_session(self) -> EditSession:
        event = self.events[0]
        if (
            event.session_id != self.session_id
            or event.frozen_policy_sha256 != self.frozen_policy_sha256
            or event.baseline_sha256 != self.baseline_sha256
            or event.policy_authorization_sha256 != self.policy_authorization_sha256
        ):
            raise ValueError("session event does not match session")
        return self
