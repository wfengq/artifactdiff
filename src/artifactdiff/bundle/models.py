"""Strict portable models for immutable ArtifactDiff Review Bundles."""

from __future__ import annotations

import re
import unicodedata
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator

from artifactdiff.models import StrictModel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")


class BundleModel(StrictModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always", strict=True)


class BundleAssurance(StrEnum):
    LOCAL = "local"
    VERIFIED = "verified"
    ENTERPRISE = "enterprise"


def validate_bundle_path(value: str) -> str:
    """Require one normalized relative path in the core/events namespaces."""
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or _DRIVE_PATH.match(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValueError("invalid bundle payload path")
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] not in {"core", "events"}
        or len(path.parts) < 2
    ):
        raise ValueError("invalid bundle payload path")
    return value


class BundlePayload(BundleModel):
    path: StrictStr = Field(min_length=1, max_length=1024)
    sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    size_bytes: StrictInt = Field(ge=0)

    _path_is_portable = field_validator("path")(validate_bundle_path)


class BundleManifest(BundleModel):
    schema_version: Literal["1.0"] = "1.0"
    assurance: BundleAssurance
    baseline_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    candidate_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    raw_verdict_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    event_chain_head: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    payloads: list[BundlePayload]
    environment: dict[StrictStr, StrictStr]

    @field_validator("payloads")
    @classmethod
    def payload_paths_are_unique_and_sorted(
        cls,
        payloads: list[BundlePayload],
    ) -> list[BundlePayload]:
        paths = [item.path for item in payloads]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("bundle payload paths must be unique and sorted")
        return payloads


class BundleVerification(BundleModel):
    valid: StrictBool
    assurance: BundleAssurance
    signature_valid_at_creation: StrictBool | None = None
    currently_trusted: StrictBool | None = None
    event_chain_valid: StrictBool
    manifest_signer_identity: StrictStr | None = None
    manifest_signer_fingerprint: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    errors: list[StrictStr] = Field(default_factory=list)
