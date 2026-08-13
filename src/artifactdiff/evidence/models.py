"""Strict privacy-scoped evidence index models."""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import ConfigDict, Field, StrictInt, StrictStr, field_validator, model_validator

from artifactdiff.models import StrictModel
from artifactdiff.policy import EvidenceMode


class EvidenceModel(StrictModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always", strict=True)


class EvidenceKind(StrEnum):
    SOURCE_HASH = "source_hash"
    EXCERPT = "excerpt"
    CHANGED_REGION = "changed_region"
    FULL_PAGE = "full_page"
    FULL_REPORT = "full_report"
    SOURCE_CONTRACT = "source_contract"


class EvidenceItem(EvidenceModel):
    kind: EvidenceKind
    path: StrictStr = Field(min_length=1, max_length=1024)
    sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: StrictInt = Field(ge=0)
    finding_ids: list[StrictStr] = Field(default_factory=list)
    excerpt_characters: StrictInt = Field(default=0, ge=0, le=500)

    @field_validator("path")
    @classmethod
    def path_is_portable(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\x00" in value
            or "\\" in value
            or value.startswith("/")
            or unicodedata.normalize("NFC", value) != value
            or path.as_posix() != value
            or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
        ):
            raise ValueError("invalid evidence path")
        return value


class EvidenceIndex(EvidenceModel):
    schema_version: Literal["1.0"] = "1.0"
    mode: EvidenceMode
    items: list[EvidenceItem]

    @field_validator("items")
    @classmethod
    def items_are_unique_and_sorted(cls, items: list[EvidenceItem]) -> list[EvidenceItem]:
        paths = [item.path for item in items]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("evidence paths must be unique and sorted")
        return items

    @model_validator(mode="after")
    def mode_enforces_privacy_boundary(self) -> EvidenceIndex:
        minimal = {
            EvidenceKind.SOURCE_HASH,
            EvidenceKind.EXCERPT,
            EvidenceKind.CHANGED_REGION,
        }
        full = minimal | {EvidenceKind.FULL_PAGE, EvidenceKind.FULL_REPORT}
        allowed = {
            EvidenceMode.MINIMAL: minimal,
            EvidenceMode.FULL: full,
            EvidenceMode.SEALED: full | {EvidenceKind.SOURCE_CONTRACT},
        }[self.mode]
        if any(item.kind not in allowed for item in self.items):
            raise ValueError("evidence item is not allowed by privacy mode")
        return self
