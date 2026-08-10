"""Strict, portable facts and verdicts for contract verification."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, StrictStr, field_validator

from artifactdiff.contract.models import (
    DocumentFeatureKind,
    EntityKind,
    EvidenceRef,
    ProtectedRegionKind,
)
from artifactdiff.contract.selectors import SelectorResolutionStatus
from artifactdiff.models import StrictModel


def _require_text(value: object) -> object:
    if not isinstance(value, str):
        raise ValueError("value must be text")  # noqa: TRY004
    return value


def _require_optional_text(value: object) -> object:
    if value is None:
        return value
    return _require_text(value)


def _require_ordered(value: object) -> object:
    if not isinstance(value, (list, tuple)):
        raise ValueError("collection must be ordered")  # noqa: TRY004
    return value


MAX_EVIDENCE_EXCERPT_CHARACTERS = 512
MAX_FINDING_TEXT_CHARACTERS = 512
MAX_FINDING_LOCATIONS = 32
MAX_VERDICT_FINDINGS = 1_000


def finding_id(
    *,
    rule_id: str,
    rule_version: str,
    location: str,
    before_fingerprint: str | None,
    after_fingerprint: str | None,
) -> str:
    """Hash the stable identity of one finding into its public identifier."""
    raw = json.dumps(
        [rule_id, rule_version, location, before_fingerprint, after_fingerprint],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"finding-{hashlib.sha256(raw).hexdigest()[:24]}"


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


class FindingOutcome(StrEnum):
    PASS = "pass"
    REVIEW = "review"
    FAIL = "fail"


class FindingEvidence(FactModel):
    before_fingerprint: StrictStr | None = Field(default=None, max_length=128)
    after_fingerprint: StrictStr | None = Field(default=None, max_length=128)
    before_excerpt: StrictStr | None = Field(
        default=None, max_length=MAX_EVIDENCE_EXCERPT_CHARACTERS
    )
    after_excerpt: StrictStr | None = Field(
        default=None, max_length=MAX_EVIDENCE_EXCERPT_CHARACTERS
    )
    locations: list[EvidenceRef] = Field(default_factory=list, max_length=MAX_FINDING_LOCATIONS)

    _locations_are_ordered = field_validator("locations", mode="before")(_require_ordered)


class Finding(FactModel):
    id: StrictStr = Field(pattern=r"^finding-[0-9a-f]{24}$")
    rule_id: StrictStr = Field(min_length=1, max_length=128)
    rule_version: Literal["1.0"] = "1.0"
    outcome: FindingOutcome
    location: StrictStr = Field(min_length=1, max_length=MAX_FINDING_TEXT_CHARACTERS)
    selector_status: SelectorResolutionStatus | None = None
    evidence: FindingEvidence
    remediation: StrictStr = Field(min_length=1, max_length=MAX_FINDING_TEXT_CHARACTERS)
    approvable: StrictBool = False

    _labels_are_text = field_validator("rule_id", "rule_version", "outcome", mode="before")(
        _require_text
    )
    _selector_status_is_optional_text = field_validator("selector_status", mode="before")(
        _require_optional_text
    )


class RawVerdict(FactModel):
    schema_version: Literal["1.0"] = "1.0"
    outcome: FindingOutcome
    policy_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    findings: list[Finding] = Field(max_length=MAX_VERDICT_FINDINGS)

    _labels_are_text = field_validator("schema_version", "outcome", mode="before")(_require_text)
    _findings_are_ordered = field_validator("findings", mode="before")(_require_ordered)

    def canonical_bytes(self) -> bytes:
        """Serialize deterministic UTF-8 JSON for later reporting."""
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
