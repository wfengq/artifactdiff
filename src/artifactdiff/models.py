"""Portable, strict public models for ArtifactDiff results."""

from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from artifactdiff.normalize import sha256_file


class StrictModel(BaseModel):
    """Pydantic base model that rejects unrecognized fields."""

    model_config = ConfigDict(extra="forbid")


class ContentType(StrEnum):
    PAGE = "page"
    PDF_TEXT = "pdf_text"
    HEADING = "heading"
    PARAGRAPH = "paragraph"
    TABLE = "table"
    HEADER = "header"
    FOOTER = "footer"


class Rect(StrictModel):
    x0: float
    y0: float
    x1: float
    y1: float


class ContentBlock(StrictModel):
    id: str
    ordinal: int
    page_index: int | None = None
    content_type: ContentType
    text: str
    normalized_text: str
    bbox: Rect | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class PageSnapshot(StrictModel):
    index: int
    width: float
    height: float
    text: str
    normalized_text: str
    blocks: list[ContentBlock] = Field(default_factory=list)
    render_path: str | None = None


class DocumentSnapshot(StrictModel):
    source_path: str
    format: Literal["pdf", "docx"]
    sha256: str
    size_bytes: int
    page_count: int | None = None
    pages: list[PageSnapshot] = Field(default_factory=list)
    blocks: list[ContentBlock] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        pages: list[PageSnapshot],
        blocks: list[ContentBlock],
        warnings: list[str] | None = None,
        metadata: dict[str, JsonValue] | None = None,
    ) -> "DocumentSnapshot":
        format_name = cast(Literal["pdf", "docx"], path.suffix.lstrip(".").casefold())
        return cls(
            source_path=str(path),
            format=format_name,
            sha256=sha256_file(path),
            size_bytes=path.stat().st_size,
            page_count=len(pages) if pages else None,
            pages=pages,
            blocks=blocks,
            warnings=warnings or [],
            metadata=metadata or {},
        )


class SourceDescriptor(StrictModel):
    path: str
    sha256: str
    format: Literal["pdf", "docx"]
    size_bytes: int

    @classmethod
    def from_path(cls, path: Path) -> "SourceDescriptor":
        format_name = cast(Literal["pdf", "docx"], path.suffix.lstrip(".").casefold())
        return cls(
            path=str(path),
            sha256=sha256_file(path),
            size_bytes=path.stat().st_size,
            format=format_name,
        )


class BlockRef(StrictModel):
    block_id: str
    ordinal: int
    page_index: int | None = None
    text: str


class SemanticChange(StrictModel):
    id: str
    kind: Literal["added", "removed", "modified", "moved"]
    content_type: ContentType
    severity: Literal["info", "warning"] = "info"
    similarity: float = Field(ge=0.0, le=1.0)
    before: BlockRef | None = None
    after: BlockRef | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)


class VisualPageChange(StrictModel):
    id: str
    before_page: int | None = None
    after_page: int | None = None
    changed_pixel_ratio: float = Field(ge=0.0, le=1.0)
    regions: list[Rect] = Field(default_factory=list)


class ComparisonSummary(StrictModel):
    added: int = 0
    removed: int = 0
    modified: int = 0
    moved: int = 0
    total_changes: int = 0
    visual_change_ratio: float = 0.0


class ComparisonResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    engine_version: str = "0.1.0"
    status: Literal["unchanged", "changed", "partial"]
    before: SourceDescriptor
    after: SourceDescriptor
    summary: ComparisonSummary = Field(default_factory=ComparisonSummary)
    changes: list[SemanticChange] = Field(default_factory=list)
    visual_changes: list[VisualPageChange] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)
    duration_ms: int = 0

    @classmethod
    def unchanged(
        cls, before: SourceDescriptor, after: SourceDescriptor
    ) -> "ComparisonResult":
        return cls(status="unchanged", before=before, after=after)
