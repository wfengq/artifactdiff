# ArtifactDiff MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, offline PDF/DOCX comparison package with a local CLI, stdio MCP server, versioned JSON output, and a self-contained visual HTML report.

**Architecture:** Format adapters create a common document snapshot, alignment and diff modules produce typed semantic and visual changes, and one comparison service writes the versioned reports. Thin CLI and MCP adapters call that service so human and agent behavior remains identical.

**Tech Stack:** Python 3.11+, Typer, Pydantic 2, official Python MCP SDK, pypdfium2, pdfplumber, python-docx, Pillow, Jinja2, pytest, Ruff, mypy, ReportLab test fixtures.

## Global Constraints

- Support Python 3.11 or newer on Windows, macOS, and Linux.
- Process documents locally without model calls, network requests, accounts, telemetry, or remote assets.
- Support PDF and DOCX only in version 0.1.
- Keep LibreOffice optional; DOCX semantic comparison must work without it.
- Produce `report.json` using schema version `1.0` and a self-contained `report.html`.
- Return CLI exit code `0` on successful comparison, `1` only when `--fail-on-change` is satisfied, and `2` on operational failure.
- Reject files larger than 100 MB or documents over 500 pages unless `force=True`.
- MCP tools accept absolute local paths only and never embed page images in model context.
- Start external processes with argument arrays and `shell=False`.
- Use test-driven development for every behavior and keep commits scoped to one task.

## Planned File Structure

```text
pyproject.toml                         Packaging, dependencies, commands, tool configuration
README.md                              Installation, quick start, MCP configuration, limitations
LICENSE                                MIT license for open-source distribution
.github/workflows/ci.yml               Cross-platform lint, type, and test matrix
src/artifactdiff/__init__.py           Package version
src/artifactdiff/errors.py             Public exception hierarchy and exit semantics
src/artifactdiff/models.py             Versioned snapshot and comparison models
src/artifactdiff/normalize.py          Deterministic text normalization and fingerprints
src/artifactdiff/limits.py              Path, format, size, and page-count validation
src/artifactdiff/alignment.py           Generic page/block sequence alignment
src/artifactdiff/semantic.py            Typed semantic change construction
src/artifactdiff/visual.py              Pixel diff, heatmap, and changed regions
src/artifactdiff/formats/base.py        Format-adapter protocol and registry
src/artifactdiff/formats/pdf.py         PDF parsing and rendering
src/artifactdiff/formats/docx.py        DOCX logical structure parsing
src/artifactdiff/libreoffice.py         Optional isolated DOCX-to-PDF conversion
src/artifactdiff/service.py             End-to-end comparison and inspection services
src/artifactdiff/reporting/json.py      Atomic versioned JSON writer
src/artifactdiff/reporting/html.py      Offline HTML report renderer
src/artifactdiff/reporting/template.html Embedded report UI template
src/artifactdiff/cli.py                 Typer commands and exit codes
src/artifactdiff/mcp_server.py          FastMCP tools and stdio entry point
tests/factories.py                      Deterministic PDF/DOCX fixtures
tests/unit/                             Focused algorithm and model tests
tests/integration/                      CLI, service, report, and MCP tests
scripts/create_demo.py                  Reproducible end-to-end demo report
```

---

### Task 1: Package foundation, models, normalization, and input limits

**Files:**
- Create: `pyproject.toml`
- Create: `src/artifactdiff/__init__.py`
- Create: `src/artifactdiff/errors.py`
- Create: `src/artifactdiff/models.py`
- Create: `src/artifactdiff/normalize.py`
- Create: `src/artifactdiff/limits.py`
- Create: `tests/unit/test_models.py`
- Create: `tests/unit/test_normalize.py`
- Create: `tests/unit/test_limits.py`

**Interfaces:**
- Produces: `normalize_text(text: str) -> str`
- Produces: `fingerprint(text: str) -> str`
- Produces: `sha256_file(path: Path) -> str`
- Produces: `validate_source(path: Path, *, force: bool, require_absolute: bool = False) -> Path`
- Produces: Pydantic models `Rect`, `ContentBlock`, `PageSnapshot`, `DocumentSnapshot`, `SourceDescriptor`, `BlockRef`, `SemanticChange`, `VisualPageChange`, `ComparisonSummary`, and `ComparisonResult`
- Produces: `ArtifactDiffError`, `InputValidationError`, `UnsupportedFormatError`, `ResourceLimitError`, and `RenderUnavailableError`

- [ ] **Step 1: Write failing model and normalization tests**

```python
from artifactdiff.models import ComparisonResult
from artifactdiff.normalize import fingerprint, normalize_text


def test_normalize_text_is_deterministic() -> None:
    assert normalize_text("  Hello\u00a0  WORLD\r\n") == "hello world"
    assert fingerprint("Hello world") == fingerprint(" hello   WORLD ")


def test_comparison_schema_defaults_to_v1() -> None:
    result = ComparisonResult.model_validate({
        "status": "unchanged",
        "before": {"path": "a.pdf", "sha256": "a" * 64, "format": "pdf", "size_bytes": 1},
        "after": {"path": "b.pdf", "sha256": "a" * 64, "format": "pdf", "size_bytes": 1},
        "summary": {},
    })
    assert result.schema_version == "1.0"
    assert result.changes == []
```

- [ ] **Step 2: Run the focused tests and verify the package is absent**

Run: `python -m pytest tests/unit/test_models.py tests/unit/test_normalize.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'artifactdiff'`.

- [ ] **Step 3: Add packaging and minimal public models**

```toml
[build-system]
requires = ["hatchling>=1.27"]
build-backend = "hatchling.build"

[project]
name = "artifactdiff"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "jinja2>=3.1,<4",
  "mcp>=1.13,<2",
  "pdfplumber>=0.11,<1",
  "pillow>=11,<13",
  "pydantic>=2.10,<3",
  "pypdfium2>=4.30,<6",
  "python-docx>=1.1,<2",
  "typer>=0.15,<1",
]

[project.optional-dependencies]
dev = ["build>=1.2", "mypy>=1.15", "pytest>=8.3", "reportlab>=4.2", "ruff>=0.11"]

[project.scripts]
artifactdiff = "artifactdiff.cli:app"
artifactdiff-mcp = "artifactdiff.mcp_server:main"

[tool.hatch.build.targets.wheel]
packages = ["src/artifactdiff"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.mypy]
python_version = "3.11"
ignore_missing_imports = true
strict = true
```

```python
# src/artifactdiff/normalize.py
import hashlib
import re
import unicodedata


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", normalized).strip().casefold()


def fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
```

Define enum-backed Pydantic models with `extra="forbid"`. Store paths as strings in serialized results so reports are portable. Use these exact public fields and factories:

```python
class StrictModel(BaseModel):
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
            format=format_name,
            size_bytes=path.stat().st_size,
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
```

- [ ] **Step 4: Add failing source-limit tests**

```python
from pathlib import Path
import pytest

from artifactdiff.errors import InputValidationError, ResourceLimitError
from artifactdiff.limits import validate_source


def test_validate_source_rejects_relative_path_for_mcp(tmp_path: Path) -> None:
    relative = Path("sample.pdf")
    with pytest.raises(InputValidationError, match="absolute"):
        validate_source(relative, force=False, require_absolute=True)


def test_validate_source_rejects_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "large.pdf"
    source.write_bytes(b"%PDF")
    monkeypatch.setattr("artifactdiff.limits.MAX_BYTES", 3)
    with pytest.raises(ResourceLimitError, match="100 MB"):
        validate_source(source, force=False)
```

- [ ] **Step 5: Implement exact validation behavior**

```python
# src/artifactdiff/limits.py
from pathlib import Path

from artifactdiff.errors import InputValidationError, ResourceLimitError, UnsupportedFormatError

MAX_BYTES = 100 * 1024 * 1024
SUPPORTED_SUFFIXES = {".pdf", ".docx"}


def validate_source(path: Path, *, force: bool, require_absolute: bool = False) -> Path:
    if require_absolute and not path.is_absolute():
        raise InputValidationError(f"Path must be absolute: {path}")
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise InputValidationError(f"Source is not a readable file: {resolved}")
    if resolved.suffix.casefold() not in SUPPORTED_SUFFIXES:
        raise UnsupportedFormatError(f"Supported formats are PDF and DOCX: {resolved}")
    if not force and resolved.stat().st_size > MAX_BYTES:
        raise ResourceLimitError(f"File exceeds the 100 MB limit: {resolved}")
    return resolved
```

- [ ] **Step 6: Run foundation checks**

Run: `python -m pip install -e ".[dev]"`

Run: `python -m pytest tests/unit/test_models.py tests/unit/test_normalize.py tests/unit/test_limits.py -q`

Run: `python -m ruff check src tests`

Expected: all tests pass and Ruff reports no errors.

- [ ] **Step 7: Commit the foundation**

```bash
git add pyproject.toml src/artifactdiff tests/unit
git commit -m "feat: establish ArtifactDiff data model"
```

---

### Task 2: Deterministic sequence alignment and semantic changes

**Files:**
- Create: `src/artifactdiff/alignment.py`
- Create: `src/artifactdiff/semantic.py`
- Create: `tests/unit/test_alignment.py`
- Create: `tests/unit/test_semantic.py`

**Interfaces:**
- Consumes: `ContentBlock`, `DocumentSnapshot`, `SemanticChange`, `normalize_text`
- Produces: `AlignedPair[T]` dataclass with `before: T | None`, `after: T | None`, and `similarity: float`
- Produces: `align_sequences(before: Sequence[T], after: Sequence[T], *, key: Callable[[T], str], threshold: float = 0.45) -> list[AlignedPair[T]]`
- Produces: `diff_snapshots(before: DocumentSnapshot, after: DocumentSnapshot) -> list[SemanticChange]`

- [ ] **Step 1: Write failing insertion and replacement alignment tests**

```python
from artifactdiff.alignment import align_sequences


def test_alignment_does_not_shift_after_insertion() -> None:
    pairs = align_sequences(["a", "b", "c"], ["a", "new", "b", "c"], key=str)
    assert [(p.before, p.after) for p in pairs] == [
        ("a", "a"), (None, "new"), ("b", "b"), ("c", "c")
    ]


def test_alignment_pairs_similar_replacement() -> None:
    pairs = align_sequences(["quarterly revenue"], ["quarterly net revenue"], key=str)
    assert pairs[0].before == "quarterly revenue"
    assert pairs[0].after == "quarterly net revenue"
    assert pairs[0].similarity > 0.7
```

- [ ] **Step 2: Run alignment tests and verify failure**

Run: `python -m pytest tests/unit/test_alignment.py -q`

Expected: import fails because `artifactdiff.alignment` does not exist.

- [ ] **Step 3: Implement alignment with exact matches plus deterministic replacement pairing**

```python
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Callable, Generic, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class AlignedPair(Generic[T]):
    before: T | None
    after: T | None
    similarity: float


def align_sequences(
    before: Sequence[T],
    after: Sequence[T],
    *,
    key: Callable[[T], str],
    threshold: float = 0.45,
) -> list[AlignedPair[T]]:
    matcher = SequenceMatcher(a=[key(item) for item in before], b=[key(item) for item in after], autojunk=False)
    pairs: list[AlignedPair[T]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            pairs.extend(AlignedPair(left, right, 1.0) for left, right in zip(before[i1:i2], after[j1:j2]))
        elif tag == "delete":
            pairs.extend(AlignedPair(item, None, 0.0) for item in before[i1:i2])
        elif tag == "insert":
            pairs.extend(AlignedPair(None, item, 0.0) for item in after[j1:j2])
        else:
            pairs.extend(_pair_replacements(before[i1:i2], after[j1:j2], key=key, threshold=threshold))
    return pairs
```

Implement `_pair_replacements` by sorting candidate `(similarity, before_index, after_index)` tuples by `(-similarity, before_index, after_index)`, selecting unused pairs at or above the threshold, and emitting unmatched items in source order. This tie-breaking rule makes output reproducible.

- [ ] **Step 4: Write failing semantic classification tests**

```python
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot
from artifactdiff.semantic import diff_snapshots


def block(ordinal: int, text: str) -> ContentBlock:
    return ContentBlock(
        id=f"b{ordinal}", ordinal=ordinal, content_type=ContentType.PARAGRAPH,
        text=text, normalized_text=text.casefold(), metadata={}
    )


def test_semantic_diff_classifies_modified_block() -> None:
    before = DocumentSnapshot(source_path="a.docx", format="docx", sha256="a" * 64, size_bytes=1, blocks=[block(0, "Old total")])
    after = DocumentSnapshot(source_path="b.docx", format="docx", sha256="b" * 64, size_bytes=1, blocks=[block(0, "New total")])
    changes = diff_snapshots(before, after)
    assert len(changes) == 1
    assert changes[0].kind == "modified"
    assert changes[0].before.text == "Old total"
    assert changes[0].after.text == "New total"
```

- [ ] **Step 5: Implement semantic diff and conservative move detection**

```python
def diff_snapshots(before: DocumentSnapshot, after: DocumentSnapshot) -> list[SemanticChange]:
    pairs = align_sequences(
        before.blocks,
        after.blocks,
        key=lambda block: f"{block.content_type}:{block.normalized_text}",
    )
    changes = [_change_from_pair(pair) for pair in pairs if not _pair_is_unchanged(pair)]
    return _promote_exact_moves(changes)
```

`_promote_exact_moves` may combine one removed and one added block only when content type and normalized text are identical and unique among unmatched changes. All ambiguous matches remain an addition and a removal.

- [ ] **Step 6: Run algorithm checks**

Run: `python -m pytest tests/unit/test_alignment.py tests/unit/test_semantic.py -q`

Run: `python -m mypy src/artifactdiff/alignment.py src/artifactdiff/semantic.py`

Expected: tests and type checks pass.

- [ ] **Step 7: Commit alignment and semantic diff**

```bash
git add src/artifactdiff/alignment.py src/artifactdiff/semantic.py tests/unit/test_alignment.py tests/unit/test_semantic.py
git commit -m "feat: add deterministic semantic alignment"
```

---

### Task 3: PDF format adapter and page rendering

**Files:**
- Create: `src/artifactdiff/formats/__init__.py`
- Create: `src/artifactdiff/formats/base.py`
- Create: `src/artifactdiff/formats/pdf.py`
- Create: `tests/factories.py`
- Create: `tests/unit/test_pdf_adapter.py`

**Interfaces:**
- Consumes: `DocumentSnapshot`, `PageSnapshot`, `ContentBlock`, `Rect`, `fingerprint`
- Produces: `FormatAdapter` protocol with `load(path: Path, *, render: bool, workdir: Path, force: bool = False) -> DocumentSnapshot`
- Produces: `PdfAdapter.load(path: Path, *, render: bool, workdir: Path, force: bool = False) -> DocumentSnapshot`
- Produces: `adapter_for(path: Path) -> FormatAdapter`

- [ ] **Step 1: Create a deterministic two-page PDF fixture and failing adapter test**

```python
# tests/factories.py
from pathlib import Path
from reportlab.pdfgen.canvas import Canvas


def make_pdf(path: Path, pages: list[list[tuple[float, float, str]]]) -> Path:
    canvas = Canvas(str(path), pagesize=(612, 792), pageCompression=0)
    canvas.setAuthor("ArtifactDiff Tests")
    for page in pages:
        for x, y, text in page:
            canvas.drawString(x, y, text)
        canvas.showPage()
    canvas.save()
    return path
```

```python
def test_pdf_adapter_extracts_text_geometry_and_renders(tmp_path: Path) -> None:
    source = make_pdf(tmp_path / "sample.pdf", [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]])
    snapshot = PdfAdapter().load(source, render=True, workdir=tmp_path / "work")
    assert snapshot.page_count == 2
    assert snapshot.pages[0].text == "Revenue 100"
    assert snapshot.pages[0].blocks[0].bbox is not None
    assert Path(snapshot.pages[0].render_path).is_file()
```

- [ ] **Step 2: Run the PDF adapter test and verify failure**

Run: `python -m pytest tests/unit/test_pdf_adapter.py -q`

Expected: import fails because `artifactdiff.formats.pdf` does not exist.

- [ ] **Step 3: Define the adapter protocol and registry**

```python
from pathlib import Path
from typing import Protocol

from artifactdiff.models import DocumentSnapshot


class FormatAdapter(Protocol):
    def load(self, path: Path, *, render: bool, workdir: Path, force: bool = False) -> DocumentSnapshot:
        raise NotImplementedError


def adapter_for(path: Path) -> FormatAdapter:
    suffix = path.suffix.casefold()
    if suffix == ".pdf":
        from artifactdiff.formats.pdf import PdfAdapter
        return PdfAdapter()
    if suffix == ".docx":
        from artifactdiff.formats.docx import DocxAdapter
        return DocxAdapter()
    raise UnsupportedFormatError(f"Supported formats are PDF and DOCX: {path}")
```

- [ ] **Step 4: Implement PDF extraction and rendering**

Open the PDF with `pdfplumber.open(path)`. For each page, call `extract_words(use_text_flow=True, keep_blank_chars=False)`, group words whose `top` values differ by at most 3 points, and create one `ContentBlock` per line. Preserve `x0`, `top`, `x1`, and `bottom` as `Rect` geometry. Reject more than 500 pages unless forced.

Render with pypdfium2 using a fixed scale of `2.0`, convert to RGB, and save `page-0001.png` names below `workdir / "pages"`.

```python
class PdfAdapter:
    def load(self, path: Path, *, render: bool, workdir: Path, force: bool = False) -> DocumentSnapshot:
        with pdfplumber.open(path) as pdf:
            if not force and len(pdf.pages) > 500:
                raise ResourceLimitError(f"Document exceeds the 500 page limit: {path}")
            pages = [self._extract_page(page, index) for index, page in enumerate(pdf.pages)]
        if render:
            self._render_pages(path, pages, workdir)
        blocks = [block for page in pages for block in page.blocks]
        return DocumentSnapshot.from_path(path, pages=pages, blocks=blocks)
```

Catch PDFium and pdfminer password/corruption exceptions and raise `InputValidationError` with the path and either `encrypted PDF` or `invalid PDF` in the message.

- [ ] **Step 5: Add page-limit and corrupt-PDF tests**

```python
def test_pdf_adapter_rejects_corrupt_pdf(tmp_path: Path) -> None:
    source = tmp_path / "broken.pdf"
    source.write_bytes(b"not a pdf")
    with pytest.raises(InputValidationError, match="invalid PDF"):
        PdfAdapter().load(source, render=False, workdir=tmp_path / "work")
```

- [ ] **Step 6: Run PDF checks**

Run: `python -m pytest tests/unit/test_pdf_adapter.py -q`

Expected: extraction, rendering, limit, and corruption tests pass.

- [ ] **Step 7: Commit the PDF adapter**

```bash
git add src/artifactdiff/formats tests/factories.py tests/unit/test_pdf_adapter.py
git commit -m "feat: parse and render PDF documents"
```

---

### Task 4: DOCX structure adapter and optional LibreOffice rendering

**Files:**
- Create: `src/artifactdiff/formats/docx.py`
- Create: `src/artifactdiff/libreoffice.py`
- Create: `tests/unit/test_docx_adapter.py`
- Create: `tests/unit/test_libreoffice.py`
- Modify: `tests/factories.py`

**Interfaces:**
- Consumes: `DocumentSnapshot`, `ContentBlock`, `ContentType`, `PdfAdapter`
- Produces: `DocxAdapter.load(path: Path, *, render: bool, workdir: Path, force: bool = False) -> DocumentSnapshot`
- Produces: `find_libreoffice() -> Path | None`
- Produces: `convert_docx_to_pdf(source: Path, output_dir: Path, executable: Path) -> Path`

- [ ] **Step 1: Add DOCX fixture generation and failing structure test**

```python
from docx import Document


def make_docx(path: Path, *, heading: str, paragraphs: list[str], rows: list[list[str]]) -> Path:
    document = Document()
    document.add_heading(heading, level=1)
    for text in paragraphs:
        document.add_paragraph(text)
    table = document.add_table(rows=len(rows), cols=len(rows[0]))
    for row_index, row in enumerate(rows):
        for column_index, value in enumerate(row):
            table.cell(row_index, column_index).text = value
    document.save(path)
    return path
```

```python
def test_docx_adapter_preserves_heading_paragraph_table_order(tmp_path: Path) -> None:
    source = make_docx(
        tmp_path / "sample.docx", heading="Q2 Results",
        paragraphs=["Revenue increased."], rows=[["Region", "Total"], ["APAC", "100"]],
    )
    snapshot = DocxAdapter().load(source, render=False, workdir=tmp_path / "work")
    assert [block.content_type for block in snapshot.blocks[:3]] == ["heading", "paragraph", "table"]
    assert snapshot.blocks[0].metadata["level"] == 1
    assert snapshot.blocks[2].metadata == {"rows": 2, "columns": 2}
```

- [ ] **Step 2: Run DOCX test and verify failure**

Run: `python -m pytest tests/unit/test_docx_adapter.py -q`

Expected: import fails because `artifactdiff.formats.docx` does not exist.

- [ ] **Step 3: Implement ordered OOXML body traversal**

```python
def iter_body_items(document: Document) -> Iterator[Paragraph | Table]:
    for child in document.element.body.iterchildren():
        if child.tag == qn("w:p"):
            yield Paragraph(child, document)
        elif child.tag == qn("w:tbl"):
            yield Table(child, document)
```

Map paragraph styles beginning with `Heading ` to `ContentType.HEADING` and parse the numeric level. Skip empty body paragraphs. Convert a table to tab-separated cells and newline-separated rows while recording exact row and column counts. Append unique non-empty section headers and footers after body blocks with `ContentType.HEADER` and `ContentType.FOOTER`.

- [ ] **Step 4: Write failing LibreOffice discovery and command tests**

```python
def test_find_libreoffice_prefers_explicit_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable = tmp_path / "soffice.exe"
    executable.write_bytes(b"")
    monkeypatch.setenv("ARTIFACTDIFF_LIBREOFFICE", str(executable))
    assert find_libreoffice() == executable.resolve()


def test_conversion_uses_argument_array(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: calls.append(args) or CompletedProcess(args, 0, "", ""))
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")
    expected = tmp_path / "out" / "input.pdf"
    expected.parent.mkdir()
    expected.write_bytes(b"%PDF")
    assert convert_docx_to_pdf(source, expected.parent, tmp_path / "soffice") == expected
    assert calls[0][0] == str(tmp_path / "soffice")
```

- [ ] **Step 5: Implement isolated optional conversion**

```python
def convert_docx_to_pdf(source: Path, output_dir: Path, executable: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    profile = output_dir / ".libreoffice-profile"
    profile.mkdir()
    args = [
        str(executable),
        f"-env:UserInstallation={profile.resolve().as_uri()}",
        "--headless", "--convert-to", "pdf", "--outdir", str(output_dir), str(source),
    ]
    completed = subprocess.run(args, shell=False, check=False, capture_output=True, text=True, timeout=120)
    converted = output_dir / f"{source.stem}.pdf"
    if completed.returncode != 0 or not converted.is_file():
        raise RenderUnavailableError(f"LibreOffice could not render {source}: {completed.stderr.strip()}")
    return converted
```

`DocxAdapter.load(path, render=True, workdir=workdir, force=force)` must attempt conversion only when `find_libreoffice()` returns a path. On missing or failed conversion, it adds a warning to the snapshot and returns semantic blocks. On success, it loads rendered pages with `PdfAdapter` while retaining DOCX logical blocks.

- [ ] **Step 6: Run DOCX and conversion checks**

Run: `python -m pytest tests/unit/test_docx_adapter.py tests/unit/test_libreoffice.py -q`

Expected: ordered structure and optional-render tests pass without requiring LibreOffice on the test machine.

- [ ] **Step 7: Commit DOCX support**

```bash
git add src/artifactdiff/formats/docx.py src/artifactdiff/libreoffice.py tests/factories.py tests/unit/test_docx_adapter.py tests/unit/test_libreoffice.py
git commit -m "feat: parse DOCX structure with optional rendering"
```

---

### Task 5: Visual difference engine

**Files:**
- Create: `src/artifactdiff/visual.py`
- Create: `tests/unit/test_visual.py`

**Interfaces:**
- Consumes: rendered PNG paths and `Rect`
- Produces: `VisualAssets` dataclass with `before_image: Path`, `after_image: Path`, and `heatmap_image: Path`
- Produces: `compare_images(before: Path, after: Path, *, output_dir: Path, threshold: int = 16, tile_size: int = 32) -> tuple[VisualPageChange, VisualAssets]`

```python
@dataclass(frozen=True, slots=True)
class VisualAssets:
    before_image: Path
    after_image: Path
    heatmap_image: Path
```

- [ ] **Step 1: Write failing unchanged and localized-change tests**

```python
from PIL import Image, ImageDraw


def test_compare_images_reports_unchanged(tmp_path: Path) -> None:
    image = Image.new("RGB", (128, 128), "white")
    before = tmp_path / "before.png"
    after = tmp_path / "after.png"
    image.save(before)
    image.save(after)
    change, assets = compare_images(before, after, output_dir=tmp_path / "diff")
    assert change.changed_pixel_ratio == 0.0
    assert change.regions == []
    assert assets.heatmap_image.is_file()


def test_compare_images_finds_local_region(tmp_path: Path) -> None:
    original = Image.new("RGB", (128, 128), "white")
    changed = original.copy()
    ImageDraw.Draw(changed).rectangle((40, 40, 70, 70), fill="black")
    before, after = tmp_path / "before.png", tmp_path / "after.png"
    original.save(before)
    changed.save(after)
    result, _ = compare_images(before, after, output_dir=tmp_path / "diff", tile_size=16)
    assert 0.04 < result.changed_pixel_ratio < 0.08
    assert any(region.x0 <= 40 and region.y0 <= 40 and region.x1 >= 70 and region.y1 >= 70 for region in result.regions)
```

- [ ] **Step 2: Run visual tests and verify failure**

Run: `python -m pytest tests/unit/test_visual.py -q`

Expected: import fails because `artifactdiff.visual` does not exist.

- [ ] **Step 3: Implement deterministic canvas, mask, ratio, heatmap, and tile regions**

```python
def compare_images(
    before: Path,
    after: Path,
    *,
    output_dir: Path,
    threshold: int = 16,
    tile_size: int = 32,
) -> tuple[VisualPageChange, VisualAssets]:
    left, right = _common_canvas(Image.open(before).convert("RGB"), Image.open(after).convert("RGB"))
    difference = ImageChops.difference(left, right).convert("L")
    mask = difference.point(lambda value: 255 if value > threshold else 0)
    changed_pixels = sum(mask.histogram()[1:]) // 255
    ratio = changed_pixels / (mask.width * mask.height)
    regions = _coalesced_tile_regions(mask, tile_size)
    heatmap = _heatmap(right, mask)
    return _write_visual_result(left, right, heatmap, regions, ratio, output_dir)
```

`_common_canvas` pads both images at the top-left on a white canvas and never stretches them. `_coalesced_tile_regions` marks tiles containing changed pixels, merges horizontally adjacent tiles, then merges vertically adjacent rectangles with identical x-ranges. Clamp threshold to `0..255` and tile size to `8..256`.

- [ ] **Step 4: Add threshold and different-size tests**

```python
def test_compare_images_pads_without_stretching(tmp_path: Path) -> None:
    Image.new("RGB", (80, 100), "white").save(tmp_path / "a.png")
    Image.new("RGB", (100, 80), "white").save(tmp_path / "b.png")
    result, assets = compare_images(tmp_path / "a.png", tmp_path / "b.png", output_dir=tmp_path / "diff")
    assert Image.open(assets.before_image).size == (100, 100)
    assert Image.open(assets.after_image).size == (100, 100)
    assert result.changed_pixel_ratio > 0
```

- [ ] **Step 5: Run visual checks**

Run: `python -m pytest tests/unit/test_visual.py -q`

Expected: all visual tests pass and generated PNGs have the common canvas dimensions.

- [ ] **Step 6: Commit the visual engine**

```bash
git add src/artifactdiff/visual.py tests/unit/test_visual.py
git commit -m "feat: add deterministic visual diff engine"
```

---

### Task 6: Comparison and inspection application services with JSON output

**Files:**
- Create: `src/artifactdiff/service.py`
- Create: `src/artifactdiff/reporting/__init__.py`
- Create: `src/artifactdiff/reporting/json.py`
- Create: `tests/integration/test_service.py`
- Create: `tests/integration/test_json_report.py`

**Interfaces:**
- Consumes: format registry, semantic diff, visual diff, input limits, result models
- Produces: `CompareOptions` dataclass with `visual: bool = True`, `force: bool = False`, `pixel_threshold: int = 16`, and `tile_size: int = 32`
- Produces: `ComparisonRun` dataclass with `result: ComparisonResult`, `json_path: Path`, `html_path: Path | None`, and `visual_assets: dict[str, VisualAssets]`
- Produces: `compare_documents(before: Path, after: Path, output_dir: Path, *, options: CompareOptions) -> ComparisonRun`
- Produces: `inspect_document(path: Path, *, force: bool = False, require_absolute: bool = False, max_blocks: int = 100) -> dict[str, object]`
- Produces: `write_json(result: ComparisonResult, path: Path) -> Path`

- [ ] **Step 1: Write a failing identical-file fast-path test**

```python
def test_compare_documents_uses_hash_fast_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_pdf(tmp_path / "same.pdf", [[(72, 720, "Same")]])
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", Mock(side_effect=AssertionError("adapter called")))
    run = compare_documents(source, source, tmp_path / "report", options=CompareOptions())
    assert run.result.status == "unchanged"
    assert run.result.summary.total_changes == 0
    assert run.json_path.is_file()
```

- [ ] **Step 2: Run service test and verify failure**

Run: `python -m pytest tests/integration/test_service.py::test_compare_documents_uses_hash_fast_path -q`

Expected: import fails because `artifactdiff.service` does not exist.

- [ ] **Step 3: Implement orchestration and atomic JSON writing**

```python
def write_json(result: ComparisonResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(path)
    return path
```

```python
def compare_documents(before: Path, after: Path, output_dir: Path, *, options: CompareOptions) -> ComparisonRun:
    before = validate_source(before, force=options.force)
    after = validate_source(after, force=options.force)
    if before.suffix.casefold() != after.suffix.casefold():
        raise InputValidationError("Both inputs must have the same supported format")
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    before_descriptor = SourceDescriptor.from_path(before)
    after_descriptor = SourceDescriptor.from_path(after)
    if before_descriptor.sha256 == after_descriptor.sha256:
        result = ComparisonResult.unchanged(before_descriptor, after_descriptor)
        return _write_run(result, output_dir)
    with TemporaryDirectory(prefix="artifactdiff-") as temporary:
        workdir = Path(temporary)
        adapter = adapter_for(before)
        left = adapter.load(before, render=options.visual, workdir=workdir / "before", force=options.force)
        right = adapter.load(after, render=options.visual, workdir=workdir / "after", force=options.force)
        return _compare_snapshots(left, right, output_dir, workdir, options)
```

The snapshot comparison aligns pages by normalized page text, aligns blocks through `diff_snapshots`, computes visual diffs only for paired rendered pages, aggregates counts and weighted visual ratio, copies no temporary image into JSON, and records missing-render warnings as `status="partial"`.

- [ ] **Step 4: Add changed, partial, mismatched-format, cleanup, and inspection tests**

```python
def test_inspect_document_bounds_blocks(tmp_path: Path) -> None:
    source = make_docx(tmp_path / "many.docx", heading="Heading", paragraphs=[str(i) for i in range(150)], rows=[["A"]])
    inspection = inspect_document(source, max_blocks=10)
    assert len(inspection["blocks"]) == 10
    assert inspection["truncated"] is True


def test_compare_rejects_mismatched_formats(tmp_path: Path) -> None:
    pdf = make_pdf(tmp_path / "a.pdf", [[(72, 720, "A")]])
    docx = make_docx(tmp_path / "b.docx", heading="B", paragraphs=[], rows=[["B"]])
    with pytest.raises(InputValidationError, match="same supported format"):
        compare_documents(pdf, docx, tmp_path / "out", options=CompareOptions())
```

- [ ] **Step 5: Run service and JSON checks**

Run: `python -m pytest tests/integration/test_service.py tests/integration/test_json_report.py -q`

Expected: fast path, changed result, partial result, mismatch, bounded inspection, JSON schema, and temporary cleanup tests pass.

- [ ] **Step 6: Commit application services**

```bash
git add src/artifactdiff/service.py src/artifactdiff/reporting tests/integration/test_service.py tests/integration/test_json_report.py
git commit -m "feat: orchestrate comparisons and JSON reports"
```

---

### Task 7: Self-contained HTML report

**Files:**
- Create: `src/artifactdiff/reporting/html.py`
- Create: `src/artifactdiff/reporting/template.html`
- Create: `tests/integration/test_html_report.py`
- Modify: `src/artifactdiff/service.py`
- Modify: `tests/factories.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `ComparisonResult` and `dict[str, VisualAssets]`
- Produces: `write_html(result: ComparisonResult, visual_assets: dict[str, VisualAssets], path: Path) -> Path`
- Updates: `compare_documents(before: Path, after: Path, output_dir: Path, *, options: CompareOptions) -> ComparisonRun` so every successful run writes both `report.json` and `report.html`

Add this concrete report fixture helper to `tests/factories.py`:

```python
def sample_changed_result_with_images(
    tmp_path: Path,
) -> tuple[ComparisonResult, dict[str, VisualAssets]]:
    before_image = tmp_path / "before.png"
    after_image = tmp_path / "after.png"
    heatmap_image = tmp_path / "heatmap.png"
    Image.new("RGB", (64, 64), "white").save(before_image)
    Image.new("RGB", (64, 64), "gray").save(after_image)
    Image.new("RGB", (64, 64), "red").save(heatmap_image)
    before = SourceDescriptor(path="before.pdf", sha256="a" * 64, format="pdf", size_bytes=1)
    after = SourceDescriptor(path="after.pdf", sha256="b" * 64, format="pdf", size_bytes=1)
    change = SemanticChange(
        id="change-1",
        kind="modified",
        content_type=ContentType.PDF_TEXT,
        similarity=0.5,
        before=BlockRef(block_id="before-1", ordinal=0, page_index=0, text="Old"),
        after=BlockRef(block_id="after-1", ordinal=0, page_index=0, text="New"),
    )
    visual = VisualPageChange(
        id="page-1", before_page=1, after_page=1, changed_pixel_ratio=1.0
    )
    result = ComparisonResult(
        status="changed",
        before=before,
        after=after,
        summary=ComparisonSummary(modified=1, total_changes=1, visual_change_ratio=1.0),
        changes=[change],
        visual_changes=[visual],
    )
    assets = VisualAssets(before_image, after_image, heatmap_image)
    return result, {"page-1": assets}
```

- [ ] **Step 1: Write a failing offline-report test**

```python
def test_html_report_is_self_contained(tmp_path: Path) -> None:
    result, assets = sample_changed_result_with_images(tmp_path)
    report = write_html(result, assets, tmp_path / "report.html")
    html = report.read_text(encoding="utf-8")
    assert "ArtifactDiff" in html
    assert 'data:image/png;base64,' in html
    assert "https://" not in html
    assert "http://" not in html
    assert 'data-mode="heatmap"' in html
    assert 'data-filter="modified"' in html
```

- [ ] **Step 2: Run HTML test and verify failure**

Run: `python -m pytest tests/integration/test_html_report.py -q`

Expected: import fails because `artifactdiff.reporting.html` does not exist.

- [ ] **Step 3: Implement Base64 encoding and strict Jinja rendering**

```python
def _data_uri(path: Path) -> str:
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def write_html(result: ComparisonResult, visual_assets: dict[str, VisualAssets], path: Path) -> Path:
    environment = Environment(
        loader=PackageLoader("artifactdiff", "reporting"),
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
    )
    visuals = {
        key: {
            "before": _data_uri(assets.before_image),
            "after": _data_uri(assets.after_image),
            "heatmap": _data_uri(assets.heatmap_image),
        }
        for key, assets in visual_assets.items()
    }
    rendered = environment.get_template("template.html").render(result=result, visuals=visuals)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)
    return path
```

- [ ] **Step 4: Implement the offline report controls**

The template must contain inline CSS and inline JavaScript only. Build these exact sections:

```html
<header class="summary">
  <h1>ArtifactDiff</h1>
  <p>{{ result.before.path }} compared with {{ result.after.path }}</p>
  <p>{{ result.summary.total_changes }} semantic changes</p>
</header>
<aside aria-label="Changed pages and document structure">
  <ol>
    {% for change in result.visual_changes %}
    <li><a href="#visual-{{ change.id }}">Page {{ change.after_page or change.before_page }}</a></li>
    {% endfor %}
  </ol>
</aside>
<main>
  <nav class="filters" aria-label="Change filters">
    <button type="button" data-filter="all" aria-pressed="true">All</button>
    <button type="button" data-filter="modified" aria-pressed="false">Modified</button>
  </nav>
  <section class="visual-comparison" data-active-mode="side-by-side">
    <button type="button" data-mode="side-by-side">Side by side</button>
    <button type="button" data-mode="swipe">Swipe</button>
    <button type="button" data-mode="overlay">Overlay</button>
    <button type="button" data-mode="heatmap">Heatmap</button>
  </section>
  <section class="semantic-changes" aria-label="Semantic changes">
    {% for change in result.changes %}
    <article data-kind="{{ change.kind }}" data-content-type="{{ change.content_type }}">
      <h2>{{ change.kind }} {{ change.content_type }}</h2>
      <del>{{ change.before.text if change.before else "" }}</del>
      <ins>{{ change.after.text if change.after else "" }}</ins>
    </article>
    {% endfor %}
  </section>
</main>
```

Mode buttons set `data-active-mode` to `side-by-side`, `swipe`, `overlay`, or `heatmap`. Filter buttons toggle semantic-change rows by `data-kind` and `data-content-type`. Buttons use `aria-pressed`; all controls are reachable by keyboard. The template displays a visible warning banner for `partial` results.

Add this package-data configuration:

```toml
[tool.hatch.build.targets.wheel.force-include]
"src/artifactdiff/reporting/template.html" = "artifactdiff/reporting/template.html"
```

- [ ] **Step 5: Test changed and unchanged reports**

Run: `python -m pytest tests/integration/test_html_report.py tests/integration/test_service.py -q`

Expected: reports contain no remote URLs, changed reports embed images, and unchanged reports render without image data.

- [ ] **Step 6: Commit the HTML report**

```bash
git add pyproject.toml src/artifactdiff/reporting src/artifactdiff/service.py tests/integration/test_html_report.py tests/integration/test_service.py
git commit -m "feat: generate offline visual HTML reports"
```

---

### Task 8: CLI commands and exit semantics

**Files:**
- Create: `src/artifactdiff/cli.py`
- Create: `tests/integration/test_cli.py`

**Interfaces:**
- Consumes: `CompareOptions`, `compare_documents`, `inspect_document`, `ArtifactDiffError`
- Produces: Typer `app` with `compare` and `inspect` commands

- [ ] **Step 1: Write failing CLI report and exit-code tests**

```python
from typer.testing import CliRunner
from artifactdiff.cli import app

runner = CliRunner()


def test_compare_writes_reports(tmp_path: Path) -> None:
    before = make_pdf(tmp_path / "before.pdf", [[(72, 720, "Old")]])
    after = make_pdf(tmp_path / "after.pdf", [[(72, 720, "New")]])
    output = tmp_path / "report"
    response = runner.invoke(app, ["compare", str(before), str(after), "--output", str(output)])
    assert response.exit_code == 0
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()


def test_fail_on_change_returns_one(tmp_path: Path) -> None:
    before = make_pdf(tmp_path / "before.pdf", [[(72, 720, "Old")]])
    after = make_pdf(tmp_path / "after.pdf", [[(72, 720, "New")]])
    response = runner.invoke(app, ["compare", str(before), str(after), "--output", str(tmp_path / "out"), "--fail-on-change"])
    assert response.exit_code == 1
```

- [ ] **Step 2: Run CLI tests and verify failure**

Run: `python -m pytest tests/integration/test_cli.py -q`

Expected: import fails because `artifactdiff.cli` does not exist.

- [ ] **Step 3: Implement exact CLI behavior**

```python
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)


@app.command()
def compare(
    before: Path,
    after: Path,
    output: Path = typer.Option(Path("artifactdiff-report"), "--output", "-o"),
    no_visual: bool = typer.Option(False, "--no-visual"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change"),
    force: bool = typer.Option(False, "--force"),
    pixel_threshold: int = typer.Option(16, min=0, max=255),
    tile_size: int = typer.Option(32, min=8, max=256),
    json_console: bool = typer.Option(False, "--json"),
) -> None:
    try:
        run = compare_documents(
            before, after, output,
            options=CompareOptions(visual=not no_visual, force=force, pixel_threshold=pixel_threshold, tile_size=tile_size),
        )
    except ArtifactDiffError as error:
        typer.echo(f"ArtifactDiff error: {error}", err=True)
        raise typer.Exit(2) from None
    typer.echo(run.result.model_dump_json() if json_console else f"{run.result.status}: {run.html_path}")
    if fail_on_change and run.result.status in {"changed", "partial"}:
        raise typer.Exit(1)
```

The `inspect` command prints a bounded JSON structure. It resolves relative paths for normal CLI use and exits `2` on public `ArtifactDiffError` exceptions without printing a traceback.

- [ ] **Step 4: Add validation, JSON-console, inspect, and no-visual tests**

Run: `python -m pytest tests/integration/test_cli.py -q`

Expected: report generation returns `0`, `--fail-on-change` returns `1`, bad input returns `2`, and `--json` prints valid JSON.

- [ ] **Step 5: Commit the CLI**

```bash
git add src/artifactdiff/cli.py tests/integration/test_cli.py
git commit -m "feat: expose document comparison CLI"
```

---

### Task 9: MCP server and contract tests

**Files:**
- Create: `src/artifactdiff/mcp_server.py`
- Create: `tests/integration/test_mcp_server.py`

**Interfaces:**
- Consumes: the same application services used by the CLI
- Produces: `mcp = FastMCP("ArtifactDiff")`
- Produces MCP tools: `compare_documents_tool(before_path: str, after_path: str, output_dir: str | None = None, visual: bool = True, force: bool = False) -> dict[str, object]`
- Produces MCP tool: `inspect_document_tool(path: str, force: bool = False) -> dict[str, object]`
- Produces: `main() -> None` running stdio transport

- [ ] **Step 1: Write failing direct tool-contract tests**

```python
@pytest.mark.anyio
async def test_compare_tool_requires_absolute_paths(tmp_path: Path) -> None:
    result = await compare_documents_tool("before.pdf", "after.pdf")
    assert result["ok"] is False
    assert "absolute" in result["error"]


@pytest.mark.anyio
async def test_compare_tool_returns_bounded_structured_result(tmp_path: Path) -> None:
    before = make_pdf(tmp_path / "before.pdf", [[(72, 720, "Old")]])
    after = make_pdf(tmp_path / "after.pdf", [[(72, 720, "New")]])
    result = await compare_documents_tool(str(before), str(after), str(tmp_path / "out"), visual=False)
    assert result["ok"] is True
    assert result["status"] == "changed"
    assert Path(result["reports"]["json"]).is_absolute()
    assert "data:image" not in json.dumps(result)
```

- [ ] **Step 2: Run MCP tests and verify failure**

Run: `python -m pytest tests/integration/test_mcp_server.py -q`

Expected: import fails because `artifactdiff.mcp_server` does not exist.

- [ ] **Step 3: Implement FastMCP tools as thin adapters**

```python
mcp = FastMCP("ArtifactDiff")


@mcp.tool(name="compare_documents")
async def compare_documents_tool(
    before_path: str,
    after_path: str,
    output_dir: str | None = None,
    visual: bool = True,
    force: bool = False,
) -> dict[str, object]:
    try:
        before = validate_source(Path(before_path), force=force, require_absolute=True)
        after = validate_source(Path(after_path), force=force, require_absolute=True)
        destination = _absolute_output_dir(output_dir, before, after)
        run = compare_documents(before, after, destination, options=CompareOptions(visual=visual, force=force))
        return _bounded_comparison_response(run)
    except ArtifactDiffError as error:
        return {"ok": False, "error_type": type(error).__name__, "error": str(error)}


def main() -> None:
    mcp.run(transport="stdio")
```

`_bounded_comparison_response` returns at most 20 key changes, the summary, warnings, status, and absolute report paths. `inspect_document_tool` invokes `inspect_document(Path(path), force=force, require_absolute=True, max_blocks=100)`. `_absolute_output_dir` requires an absolute user-supplied path; when omitted, it creates a deterministic directory under `Path.cwd() / "artifactdiff-reports"` using the first 12 characters of both source hashes.

- [ ] **Step 4: Add tool-list and bounded-inspection tests**

Use the SDK's in-memory client transport to initialize a session, call `list_tools`, and assert the names are exactly `compare_documents` and `inspect_document`. Call `inspect_document` on a 150-block fixture and assert `truncated=True` with 100 returned blocks.

Run: `python -m pytest tests/integration/test_mcp_server.py -q`

Expected: discovery, validation, successful comparison, bounded response, and error-contract tests pass.

- [ ] **Step 5: Commit the MCP server**

```bash
git add src/artifactdiff/mcp_server.py tests/integration/test_mcp_server.py
git commit -m "feat: expose ArtifactDiff MCP tools"
```

---

### Task 10: End-to-end demo, documentation, cross-platform CI, and release verification

**Files:**
- Create: `scripts/create_demo.py`
- Create: `tests/integration/test_end_to_end.py`
- Create: `README.md`
- Create: `LICENSE`
- Create: `.github/workflows/ci.yml`
- Modify: `pyproject.toml`
- Modify: `tests/factories.py`

**Interfaces:**
- Consumes: public CLI and MCP entry points
- Produces: `python scripts/create_demo.py --output demo-output`
- Produces: documented `pipx`, `uvx`, CLI, and MCP setup

Add deterministic end-to-end pairs to `tests/factories.py`:

```python
def make_demo_pdf_pair(tmp_path: Path) -> tuple[Path, Path]:
    before = make_pdf(
        tmp_path / "before.pdf",
        [[(72, 720, "Quarterly results"), (72, 690, "Revenue 100")]],
    )
    after = make_pdf(
        tmp_path / "after.pdf",
        [
            [(72, 720, "Quarterly results"), (72, 690, "Net revenue 120")],
            [(72, 720, "Appendix")],
        ],
    )
    return before, after


def make_demo_docx_pair(tmp_path: Path) -> tuple[Path, Path]:
    before = make_docx(
        tmp_path / "before.docx",
        heading="Quarterly results",
        paragraphs=["Revenue was 100."],
        rows=[["Region", "Total"], ["APAC", "40"]],
    )
    after = make_docx(
        tmp_path / "after.docx",
        heading="Quarterly net results",
        paragraphs=["Net revenue was 120."],
        rows=[["Region", "Total"], ["APAC", "55"], ["EMEA", "65"]],
    )
    return before, after
```

- [ ] **Step 1: Write a failing installed-package smoke test**

```python
def test_end_to_end_pdf_and_docx_reports(tmp_path: Path) -> None:
    pdf_before, pdf_after = make_demo_pdf_pair(tmp_path)
    docx_before, docx_after = make_demo_docx_pair(tmp_path)
    for name, before, after in [
        ("pdf", pdf_before, pdf_after),
        ("docx", docx_before, docx_after),
    ]:
        response = subprocess.run(
            [sys.executable, "-m", "artifactdiff.cli", "compare", str(before), str(after), "--output", str(tmp_path / name), "--no-visual"],
            capture_output=True, text=True, check=False,
        )
        assert response.returncode == 0, response.stderr
        report = json.loads((tmp_path / name / "report.json").read_text(encoding="utf-8"))
        assert report["schema_version"] == "1.0"
        assert report["summary"]["total_changes"] > 0
        assert (tmp_path / name / "report.html").is_file()
```

- [ ] **Step 2: Run the smoke test and record the first real integration failure**

Run: `python -m pytest tests/integration/test_end_to_end.py -q`

Expected: failure identifies any missing `__main__` invocation, package data, or fixture helper that prevents the installed workflow.

- [ ] **Step 3: Add module execution and the reproducible demo script**

Append to `src/artifactdiff/cli.py`:

```python
if __name__ == "__main__":
    app()
```

`scripts/create_demo.py` creates one PDF pair and one DOCX pair with heading, paragraph, table, inserted page, and layout-only changes, then calls `compare_documents` into `demo-output/pdf` and `demo-output/docx`. It prints the two absolute HTML paths and never checks generated demo artifacts into Git.

- [ ] **Step 4: Write the README and license around a two-minute activation path**

The first screen contains this exact sequence:

```markdown
# ArtifactDiff

Review PDF and Word changes like a code diff - locally, deterministically, and from AI agents.

```bash
pipx install artifactdiff
artifactdiff compare old.pdf new.pdf -o report
```
```

Then document:

- `uvx artifactdiff compare old.docx new.docx -o report`
- The four visual modes.
- The `--no-visual`, `--fail-on-change`, `--force`, `--json`, pixel threshold, and tile-size options.
- Optional LibreOffice discovery and `ARTIFACTDIFF_LIBREOFFICE`.
- MCP configuration using `artifactdiff-mcp` as a stdio command.
- The two tools and their absolute-path requirement.
- Privacy and offline guarantees.
- The 100 MB and 500-page limits.
- Explicit version 0.1 exclusions from the design specification.
- Development commands and license intent.

Create `LICENSE` from the canonical MIT License text, set the copyright line to `Copyright (c) 2026 sailwq`, and link to it from the README.

- [ ] **Step 5: Add cross-platform CI**

```yaml
name: CI
on:
  push:
  pull_request:
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.11", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: python -m pip install -e ".[dev]"
      - run: python -m ruff check src tests scripts
      - run: python -m mypy src/artifactdiff
      - run: python -m pytest -q
```

- [ ] **Step 6: Run complete automated verification**

Run: `python -m ruff check src tests scripts`

Run: `python -m mypy src/artifactdiff`

Run: `python -m pytest -q`

Run: `python -m build`

Run: `python scripts/create_demo.py --output demo-output`

Expected: lint, types, tests, and package build pass; both demo reports are generated.

- [ ] **Step 7: Perform report visual and offline QA**

Open `demo-output/pdf/report.html` and `demo-output/docx/report.html` in a browser. Confirm:

- Summary counts and warning banners match `report.json`.
- Side-by-side, swipe, overlay, and heatmap buttons change the active visual mode.
- Filters hide and reveal semantic rows correctly.
- Changed regions cover the fixture edits.
- There is no clipped text, overlapping UI, remote request, missing image, or unreadable contrast.
- Reloading with the network disabled preserves the complete report.

If a defect is found, add a failing test that represents it, run that test to observe failure, make the smallest fix, and repeat the full automated and visual checks.

- [ ] **Step 8: Commit documentation and release readiness**

```bash
git add README.md LICENSE .github/workflows/ci.yml pyproject.toml scripts/create_demo.py tests/integration/test_end_to_end.py src/artifactdiff/cli.py
git commit -m "docs: prepare ArtifactDiff MVP release"
```

---

## Final verification checklist

- [ ] `python -m ruff check src tests scripts` exits `0`.
- [ ] `python -m mypy src/artifactdiff` exits `0`.
- [ ] `python -m pytest -q` exits `0`.
- [ ] `python -m build` creates both wheel and source distribution.
- [ ] The PDF demo has semantic and visual changes in JSON and HTML.
- [ ] The DOCX demo has semantic changes without LibreOffice and visual changes when LibreOffice is available.
- [ ] `artifactdiff --help`, `artifactdiff compare --help`, and `artifactdiff inspect --help` render correctly.
- [ ] The MCP client discovers exactly `compare_documents` and `inspect_document`.
- [ ] MCP responses contain no Base64 images and require absolute input paths.
- [ ] HTML reports make no network requests and remain functional offline.
- [ ] Operational errors return CLI exit `2`; `--fail-on-change` returns `1`; normal comparisons return `0`.
- [ ] `git status --short` contains no generated reports, temporary profiles, build outputs, or caches.
