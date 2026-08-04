"""Strict, portable facts describing observed contract changes."""

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, StrictStr, field_validator

from artifactdiff.contract.models import (
    DocumentFeatureKind,
    EntityKind,
    EvidenceRef,
    ProtectedRegionKind,
)
from artifactdiff.models import StrictModel


def _require_text(value: object) -> object:
    if not isinstance(value, str):
        raise ValueError("value must be text")  # noqa: TRY004
    return value


def _require_ordered(value: object) -> object:
    if not isinstance(value, (list, tuple)):
        raise ValueError("collection must be ordered")  # noqa: TRY004
    return value


class FactModel(StrictModel):
    """Fact base that rejects extras and revalidates nested instances."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")


class ClauseChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    MOVED = "moved"


class ClauseChange(FactModel):
    id: StrictStr
    kind: ClauseChangeKind
    before_clause_id: StrictStr | None = None
    after_clause_id: StrictStr | None = None
    before_text: StrictStr | None = None
    after_text: StrictStr | None = None
    before_evidence: list[EvidenceRef] = Field(default_factory=list)
    after_evidence: list[EvidenceRef] = Field(default_factory=list)

    _kind_is_text = field_validator("kind", mode="before")(_require_text)
    _evidence_is_ordered = field_validator("before_evidence", "after_evidence", mode="before")(
        _require_ordered
    )


class EntityChange(FactModel):
    id: StrictStr
    kind: EntityKind
    before_value: StrictStr | None = None
    after_value: StrictStr | None = None
    clause_change_id: StrictStr

    _kind_is_text = field_validator("kind", mode="before")(_require_text)


class RegionChange(FactModel):
    id: StrictStr
    kind: ProtectedRegionKind
    before_fingerprint: StrictStr | None = None
    after_fingerprint: StrictStr | None = None

    _kind_is_text = field_validator("kind", mode="before")(_require_text)


class FeatureChange(FactModel):
    id: StrictStr
    kind: DocumentFeatureKind
    before_fingerprint: StrictStr | None = None
    after_fingerprint: StrictStr | None = None
    business_relevance: Literal["business", "non_business"]

    _text_labels = field_validator("kind", "business_relevance", mode="before")(_require_text)


class ContractChangeSet(FactModel):
    schema_version: Literal["1.0"] = "1.0"
    baseline_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    clause_changes: list[ClauseChange] = Field(default_factory=list)
    entity_changes: list[EntityChange] = Field(default_factory=list)
    region_changes: list[RegionChange] = Field(default_factory=list)
    feature_changes: list[FeatureChange] = Field(default_factory=list)
    unresolved_clause_ids: list[StrictStr] = Field(default_factory=list)

    _version_is_text = field_validator("schema_version", mode="before")(_require_text)
    _collections_are_ordered = field_validator(
        "clause_changes",
        "entity_changes",
        "region_changes",
        "feature_changes",
        "unresolved_clause_ids",
        mode="before",
    )(_require_ordered)
