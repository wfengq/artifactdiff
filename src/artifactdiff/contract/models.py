"""Strict, portable intermediate representation for contract documents."""

from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue

from artifactdiff.models import Rect, SourceDescriptor, StrictModel


class LanguageKind(StrEnum):
    CHINESE = "zh"
    ENGLISH = "en"
    BILINGUAL = "zh-en"
    OTHER = "other"


class LanguageProfile(StrictModel):
    kind: LanguageKind
    han_characters: int = 0
    latin_letters: int = 0


class EvidenceRef(StrictModel):
    block_id: str
    page_index: int | None = None
    bbox: Rect | None = None
    rendered_page_index: int | None = None
    rendered_bbox: Rect | None = None


class DocumentFeatureKind(StrEnum):
    COMMENT = "comment"
    TRACKED_REVISION = "tracked_revision"
    HIDDEN_TEXT = "hidden_text"
    EXTERNAL_LINK = "external_link"
    EMBEDDED_IMAGE = "embedded_image"
    METADATA = "metadata"


class DocumentFeature(StrictModel):
    id: str
    kind: DocumentFeatureKind
    fingerprint: str
    count: int = Field(ge=1)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    details: dict[str, JsonValue] = Field(default_factory=dict)


class ClauseLabel(StrictModel):
    printed: str
    normalized: str
    scheme: Literal[
        "chinese_article", "chinese_list", "decimal", "article", "section", "none"
    ]


class EntityKind(StrEnum):
    PARTY = "party"
    MONEY = "money"
    CURRENCY = "currency"
    DATE = "date"
    DURATION = "duration"
    PERCENTAGE = "percentage"


class ProtectedEntity(StrictModel):
    id: str
    kind: EntityKind
    text: str
    normalized_value: str
    clause_id: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class ProtectedRegionKind(StrEnum):
    HEADER = "header"
    FOOTER = "footer"
    SIGNATURE = "signature"
    SEAL = "seal"
    ATTACHMENT = "attachment"


class ProtectedRegion(StrictModel):
    id: str
    kind: ProtectedRegionKind
    text_fingerprint: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    feature_fingerprints: list[str] = Field(default_factory=list)


class ContractClause(StrictModel):
    id: str
    label: ClauseLabel
    heading: str
    ancestor_path: tuple[str, ...] = ()
    text: str
    normalized_text: str
    fingerprint: str
    parent_id: str | None = None
    child_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    entities: list[ProtectedEntity] = Field(default_factory=list)


class ContractDocument(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    source: SourceDescriptor
    language: LanguageProfile
    clauses: list[ContractClause] = Field(default_factory=list)
    tables: list[EvidenceRef] = Field(default_factory=list)
    protected_regions: list[ProtectedRegion] = Field(default_factory=list)
    entities: list[ProtectedEntity] = Field(default_factory=list)
    features: list[DocumentFeature] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
