"""Strict public models and provider protocols for ArtifactDiff trust."""

from __future__ import annotations

import base64
from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import ConfigDict, Field, JsonValue, StrictStr, field_validator, model_validator

from artifactdiff.models import StrictModel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PURPOSE_PATTERN = r"^[a-z][a-z0-9._-]{0,63}$"
_IDENTITY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class TrustModel(StrictModel):
    """Trust model that revalidates nested prebuilt instances."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always", strict=True)


class TrustRole(StrEnum):
    POLICY_AUTHORIZER = "policy_authorizer"
    FINDING_APPROVER = "finding_approver"
    ARCHIVE_SIGNER = "archive_signer"


class TrustIdentity(TrustModel):
    id: StrictStr = Field(pattern=_IDENTITY_PATTERN)
    subject_type: Literal["human", "service", "agent"]
    public_key_fingerprint: StrictStr = Field(pattern=_SHA256_PATTERN)
    public_key_pem: StrictStr = Field(min_length=1, max_length=16_384)
    roles: frozenset[TrustRole] = Field(min_length=1)
    revoked: bool = False
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @field_validator("valid_from", "valid_until")
    @classmethod
    def require_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("trust validity times must include a timezone")
        return value

    @model_validator(mode="after")
    def validity_window_is_ordered(self) -> TrustIdentity:
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_from > self.valid_until
        ):
            raise ValueError("trust validity window is reversed")
        return self


class TrustStore(TrustModel):
    schema_version: Literal["1.0"] = "1.0"
    identities: list[TrustIdentity]

    @model_validator(mode="after")
    def identities_are_unique(self) -> TrustStore:
        identities = [item.id for item in self.identities]
        fingerprints = [item.public_key_fingerprint for item in self.identities]
        if len(identities) != len(set(identities)):
            raise ValueError("trust identity IDs must be unique")
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("trust public-key fingerprints must be unique")
        return self


class SignatureEnvelope(TrustModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_fingerprint: StrictStr = Field(pattern=_SHA256_PATTERN)
    identity: StrictStr = Field(pattern=_IDENTITY_PATTERN)
    purpose: StrictStr = Field(pattern=_PURPOSE_PATTERN)
    canonical_object_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    claimed_signing_time: datetime | None = None
    trusted_time_evidence: dict[str, JsonValue] | None = None
    signature_base64: StrictStr = Field(min_length=88, max_length=88)

    @field_validator("claimed_signing_time")
    @classmethod
    def require_aware_claimed_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("claimed signing time must include a timezone")
        return value

    @field_validator("signature_base64")
    @classmethod
    def signature_is_canonical_base64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError("signature must be canonical base64") from None
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("signature must be canonical Ed25519 base64")
        return value


class PolicyAuthorization(TrustModel):
    frozen_policy_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    signature: SignatureEnvelope


class SignatureInspection(TrustModel):
    signature_valid: bool
    currently_trusted: bool
    identity: TrustIdentity | None = None
    errors: list[str] = Field(default_factory=list)


class SecretProvider(Protocol):
    def get_secret(self, identity: str) -> bytes:
        """Return private-key decryption bytes without logging them."""
        ...


class SigningProvider(Protocol):
    def sign(
        self,
        *,
        purpose: str,
        digest: str,
        required_role: TrustRole,
    ) -> SignatureEnvelope:
        """Sign one canonical digest for an authorized purpose."""
        ...
