# Contract IR Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic Chinese, English, and bilingual Contract IR with stable clause identity, protected entities, visual evidence links, and conservative cross-format selector resolution.

**Architecture:** Keep `DocumentSnapshot` as the parser boundary and add a focused `artifactdiff.contract` package above it. Contract analysis is pure and deterministic; format-specific enrichment remains in adapters. A small contract service loads one document and returns bounded Contract IR without changing existing `compare` behavior.

**Tech Stack:** Python 3.11-3.13, Pydantic 2, python-docx, pdfplumber, existing ArtifactDiff adapters and normalization utilities, pytest.

## Global Constraints

- Support DOCX-to-DOCX, PDF-to-PDF, and DOCX-to-PDF contract workflows.
- Treat Chinese, English, and bilingual Chinese-English text contracts as first-class.
- OCR, PPTX, and XLSX remain outside the 1.0 core.
- Parsing and matching are offline and deterministic; no LLM or network call participates.
- Page number, list ordinal, and transient block ID are never the primary clause identity.
- Ambiguous selector resolution never passes.
- Existing `artifactdiff compare` and `artifactdiff inspect` outputs remain compatible.
- All public models reject unknown fields with Pydantic `extra="forbid"`.

---

### Task 1: Contract IR models and language profile

**Files:**
- Create: `src/artifactdiff/contract/__init__.py`
- Create: `src/artifactdiff/contract/models.py`
- Create: `src/artifactdiff/contract/language.py`
- Create: `tests/unit/contract/test_models.py`
- Create: `tests/unit/contract/test_language.py`
- Modify: `src/artifactdiff/__init__.py`

**Interfaces:**
- Consumes: `artifactdiff.models.StrictModel`, `SourceDescriptor`, `Rect`
- Produces: `LanguageKind`, `LanguageProfile`, `EvidenceRef`, `ClauseLabel`, `EntityKind`, `ProtectedEntity`, `ProtectedRegionKind`, `ProtectedRegion`, `ContractClause`, `ContractDocument`
- Produces: `detect_language(text: str) -> LanguageProfile`

- [ ] **Step 1: Write failing model and language tests**

```python
from pydantic import ValidationError

from artifactdiff.contract.language import detect_language
from artifactdiff.contract.models import ContractDocument, LanguageKind


def test_detect_language_distinguishes_chinese_english_and_bilingual() -> None:
    assert detect_language("第四条 付款条件").kind is LanguageKind.CHINESE
    assert detect_language("Section 4 Payment Terms").kind is LanguageKind.ENGLISH
    assert detect_language("第四条 Payment Terms 付款条件").kind is LanguageKind.BILINGUAL


def test_contract_document_rejects_unknown_fields(contract_document_data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ContractDocument.model_validate({**contract_document_data, "surprise": True})
```

- [ ] **Step 2: Run the tests and verify the missing-package failure**

Run: `python -m pytest tests/unit/contract/test_models.py tests/unit/contract/test_language.py -q`

Expected: FAIL because `artifactdiff.contract` does not exist.

- [ ] **Step 3: Implement the strict Contract IR models**

```python
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


class ClauseLabel(StrictModel):
    printed: str
    normalized: str
    scheme: Literal["chinese_article", "chinese_list", "decimal", "article", "section", "none"]


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
    warnings: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Implement deterministic language detection**

Count Han characters with `"\u3400" <= char <= "\u9fff"` and Latin letters with `char.isascii() and char.isalpha()`. Return `zh-en` when both counts are at least 20% of their combined total, otherwise return the dominant supported language; return `other` when both counts are zero.

```python
def detect_language(text: str) -> LanguageProfile:
    han = sum("\u3400" <= char <= "\u9fff" for char in text)
    latin = sum(char.isascii() and char.isalpha() for char in text)
    total = han + latin
    if total == 0:
        kind = LanguageKind.OTHER
    elif han / total >= 0.2 and latin / total >= 0.2:
        kind = LanguageKind.BILINGUAL
    elif han > latin:
        kind = LanguageKind.CHINESE
    else:
        kind = LanguageKind.ENGLISH
    return LanguageProfile(kind=kind, han_characters=han, latin_letters=latin)
```

- [ ] **Step 5: Export public Contract IR types and run tests**

Run: `python -m pytest tests/unit/contract/test_models.py tests/unit/contract/test_language.py -q`

Expected: PASS, including JSON round-trip and unknown-field rejection.

- [ ] **Step 6: Commit the Contract IR schema**

```bash
git add src/artifactdiff/contract src/artifactdiff/__init__.py tests/unit/contract
git commit -m "feat: define contract intermediate representation"
```

---

### Task 2: Clause grammar, hierarchy, protected entities, and regions

**Files:**
- Create: `src/artifactdiff/contract/numbering.py`
- Create: `src/artifactdiff/contract/entities.py`
- Create: `src/artifactdiff/contract/analyzer.py`
- Create: `tests/unit/contract/test_numbering.py`
- Create: `tests/unit/contract/test_entities.py`
- Create: `tests/unit/contract/test_analyzer.py`

**Interfaces:**
- Consumes: `DocumentSnapshot`, `ContentType`, all Task 1 models
- Produces: `ClauseMarker(level: int, label: ClauseLabel, heading: str)`
- Produces: `parse_clause_marker(text: str) -> ClauseMarker | None`
- Produces: `extract_entities(text: str, clause_id: str | None, evidence: EvidenceRef) -> list[ProtectedEntity]`
- Produces: `analyze_contract(snapshot: DocumentSnapshot) -> ContractDocument`

- [ ] **Step 1: Write failing numbering and hierarchy tests**

```python
@pytest.mark.parametrize(
    ("text", "scheme", "level", "printed"),
    [
        ("第四条 付款条件", "chinese_article", 1, "第四条"),
        ("第 4 条 付款条件", "chinese_article", 1, "第 4 条"),
        ("一、付款条件", "chinese_list", 2, "一、"),
        ("（一）付款时间", "chinese_list", 3, "（一）"),
        ("4.2 Payment timing", "decimal", 2, "4.2"),
        ("Article IV Payment Terms", "article", 1, "Article IV"),
        ("Section 4.2 Payment timing", "section", 2, "Section 4.2"),
    ],
)
def test_parse_clause_marker(text: str, scheme: str, level: int, printed: str) -> None:
    marker = parse_clause_marker(text)
    assert marker is not None
    assert (marker.label.scheme, marker.level, marker.label.printed) == (scheme, level, printed)


def test_analyzer_builds_parent_child_hierarchy(snapshot_with_nested_clauses: DocumentSnapshot) -> None:
    contract = analyze_contract(snapshot_with_nested_clauses)
    assert [clause.label.printed for clause in contract.clauses] == ["第四条", "（一）", "4.2"]
    assert contract.clauses[1].parent_id == contract.clauses[0].id
    assert contract.clauses[1].ancestor_path == ("付款条件",)
```

- [ ] **Step 2: Run the focused tests and verify missing symbols**

Run: `python -m pytest tests/unit/contract/test_numbering.py tests/unit/contract/test_analyzer.py -q`

Expected: FAIL because the parser and analyzer do not exist.

- [ ] **Step 3: Implement ordered, anchored clause regexes**

Compile only these bounded patterns, in this precedence order, and normalize full-width spaces before matching:

```python
PATTERNS: tuple[tuple[str, Pattern[str], Callable[[Match[str]], int]], ...] = (
    ("chinese_article", re.compile(r"^(第\s*[一二三四五六七八九十百千零〇两0-9]+\s*条)\s*(.*)$"), lambda _: 1),
    ("article", re.compile(r"^(Article\s+[IVXLCDM0-9]+)\b[.：:]?\s*(.*)$", re.I), lambda _: 1),
    ("section", re.compile(r"^(Section\s+(\d+(?:\.\d+)*))\b[.：:]?\s*(.*)$", re.I), lambda match: match.group(2).count(".") + 1),
    ("decimal", re.compile(r"^(\d+(?:\.\d+)+)[.、：:]?\s*(.*)$"), lambda match: match.group(1).count(".") + 1),
    ("chinese_list", re.compile(r"^([一二三四五六七八九十百千]+、)\s*(.*)$"), lambda _: 2),
    ("chinese_list", re.compile(r"^（([一二三四五六七八九十百千]+)）\s*(.*)$"), lambda _: 3),
)
```

`parse_clause_marker` returns `None` on non-matches, preserves the printed marker, uses `normalize_text` for the normalized label, and never searches beyond the start of the line.

- [ ] **Step 4: Write failing deterministic entity tests**

```python
def test_extract_entities_normalizes_contract_values(evidence: EvidenceRef) -> None:
    entities = extract_entities(
        "甲方：上海示例科技有限公司；价款 RMB 10,000.00；45 天；利率 3.5%；2026年8月4日",
        "clause-4",
        evidence,
    )
    observed = {(item.kind.value, item.normalized_value) for item in entities}
    assert ("party", "上海示例科技有限公司") in observed
    assert ("money", "10000.00") in observed
    assert ("currency", "CNY") in observed
    assert ("duration", "45 day") in observed
    assert ("percentage", "3.5") in observed
    assert ("date", "2026-08-04") in observed
```

- [ ] **Step 5: Implement bounded entity extraction**

Use precompiled patterns for `甲方/乙方/丙方/Party A/Party B`, ISO and Chinese dates, currency codes and symbols, decimal money, day/month/year durations, and percentages. Normalize `RMB`, `CNY`, and `¥` to `CNY`; remove thousands separators from money; use `Decimal`; emit stable IDs from `sha256(f"{kind}\0{normalized}\0{clause_id}\0{block_id}")[:24]`; sort by source span and entity kind. Do not use general named-entity recognition.

```python
def _entity_id(kind: EntityKind, value: str, clause_id: str | None, block_id: str) -> str:
    material = f"{kind.value}\0{value}\0{clause_id or ''}\0{block_id}".encode("utf-8")
    return f"entity-{hashlib.sha256(material).hexdigest()[:24]}"
```

- [ ] **Step 6: Implement single-pass contract analysis**

Walk `snapshot.blocks` in ordinal order. Start a clause when a block is a heading or its first line has a marker. Maintain a stack keyed by marker level, append unmarked body blocks to the active clause, and create one synthetic unlabeled clause only when meaningful body text precedes the first marker. Build IDs from normalized label, ancestor path, heading, and first 160 normalized characters. Classify header/footer blocks directly; classify signature, seal, and attachment regions only from the anchored keyword sets below.

```python
SIGNATURE_TERMS = frozenset({"签字", "签名", "授权代表", "signature", "signed by"})
SEAL_TERMS = frozenset({"盖章", "公章", "印章", "seal", "company chop"})
ATTACHMENT_TERMS = frozenset({"附件", "附录", "appendix", "attachment", "schedule"})
```

Tables remain referenced in `ContractDocument.tables`, and their text is included in the active clause. Every clause and entity retains `EvidenceRef` objects back to source blocks.

- [ ] **Step 7: Run analyzer tests and regression tests**

Run: `python -m pytest tests/unit/contract tests/unit/test_docx_adapter.py tests/unit/test_pdf_adapter.py -q`

Expected: PASS; existing adapter ordering and IDs remain unchanged.

- [ ] **Step 8: Commit clause and entity analysis**

```bash
git add src/artifactdiff/contract tests/unit/contract
git commit -m "feat: analyze deterministic contract structure"
```

---

### Task 3: Deterministic document feature facts

**Files:**
- Create: `src/artifactdiff/contract/features.py`
- Create: `tests/unit/contract/test_features.py`
- Modify: `src/artifactdiff/contract/models.py`
- Modify: `src/artifactdiff/contract/analyzer.py`
- Modify: `src/artifactdiff/formats/docx.py`
- Modify: `src/artifactdiff/formats/pdf.py`
- Modify: `tests/unit/test_docx_adapter.py`
- Modify: `tests/unit/test_pdf_adapter.py`

**Interfaces:**
- Produces: `DocumentFeatureKind`, `DocumentFeature`
- Produces: `inspect_docx_features(path: Path) -> list[DocumentFeature]`
- Produces: `inspect_pdf_features(document: pdfplumber.PDF) -> list[DocumentFeature]`
- Adds: `ContractDocument.features: list[DocumentFeature]`

- [ ] **Step 1: Write failing DOCX feature tests**

```python
def test_docx_features_detect_comments_revisions_hidden_text_links_and_metadata(tmp_path: Path) -> None:
    source = make_featured_docx(tmp_path / "features.docx")
    snapshot = DocxAdapter().load(source, render=False, workdir=tmp_path / "work")
    contract = analyze_contract(snapshot)
    assert {item.kind for item in contract.features} == {
        DocumentFeatureKind.COMMENT,
        DocumentFeatureKind.TRACKED_REVISION,
        DocumentFeatureKind.HIDDEN_TEXT,
        DocumentFeatureKind.EXTERNAL_LINK,
        DocumentFeatureKind.EMBEDDED_IMAGE,
        DocumentFeatureKind.METADATA,
    }
```

- [ ] **Step 2: Implement bounded feature models and IDs**

```python
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
```

IDs hash kind, stable normalized details, evidence block IDs, and content fingerprint. Details may contain relationship type, sanitized URI scheme/host hash, metadata key, or OOXML part name, but never a full external URL or comment/hidden text in ordinary reports.

- [ ] **Step 3: Inspect DOCX OOXML feature parts**

Read the already validated package entries in sorted order. Count `w:commentReference`/comments, `w:ins` and `w:del`, `w:vanish` and `w:webHidden`, relationships with `TargetMode="External"`, and `a:blip` image relationships. Hash embedded image bytes and map their drawing paragraph to a logical block. Read core/app properties but keep only normalized keys and value fingerprints; save time, application name/version, creator, and last modifier are marked `business_relevance="non_business"`. Attach evidence when a feature can be mapped to a paragraph block; otherwise use the part name and fingerprint.

- [ ] **Step 4: Inspect PDF metadata and external annotations**

Hash sorted PDF metadata key/value pairs after excluding volatile parser fields, marking creation/modification software/time as non-business. Inspect page annotations for URI/action entries and record only URI scheme plus SHA-256 of normalized target. Record each `page.images` object by page/bounding box and a stable object/content fingerprint when exposed by the parser; otherwise fingerprint its geometry and mark extraction confidence in details. Encrypted or malformed annotation/image structures remain input errors from the adapter.

- [ ] **Step 5: Add analyzer integration and stable-diff tests**

Store serialized feature facts in `DocumentSnapshot.metadata["document_features"]`; `analyze_contract` validates them into `ContractDocument.features`. When an embedded image is in the same block or rendered neighborhood as a signature/seal keyword, include its fingerprint and evidence in the corresponding protected region. Generate the same featured document twice and assert identical feature JSON. Change one comment, hidden span, external URL, signature image, and save-time field separately and assert only the corresponding feature fingerprint changes.

Run: `python -m pytest tests/unit/contract/test_features.py tests/unit/test_docx_adapter.py tests/unit/test_pdf_adapter.py -q`

Expected: PASS with bounded, text-minimizing, stable feature facts.

- [ ] **Step 6: Commit document feature extraction**

```bash
git add src/artifactdiff/contract src/artifactdiff/formats/docx.py src/artifactdiff/formats/pdf.py tests/unit/contract/test_features.py tests/unit/test_docx_adapter.py tests/unit/test_pdf_adapter.py
git commit -m "feat: extract contract document features"
```

---

### Task 4: Rendered evidence enrichment and cross-format selectors

**Files:**
- Create: `src/artifactdiff/contract/selectors.py`
- Create: `tests/unit/contract/test_selectors.py`
- Modify: `src/artifactdiff/formats/docx.py`
- Modify: `tests/unit/test_docx_adapter.py`
- Modify: `src/artifactdiff/contract/models.py`

**Interfaces:**
- Consumes: `ContractDocument`, `ContractClause`, `PageSnapshot`, `align_sequences`
- Produces: `ClauseSelector`, `SelectorMatch`, `SelectorResolutionStatus`, `SelectorResolution`
- Produces: `resolve_baseline(document: ContractDocument, selector: ClauseSelector) -> SelectorResolution`
- Produces: `resolve_candidate(document: ContractDocument, selector: ClauseSelector) -> SelectorResolution`
- Produces: DOCX block metadata keys `rendered_page_index`, `rendered_bbox`

- [ ] **Step 1: Write failing DOCX rendered-evidence test**

```python
def test_docx_render_links_logical_blocks_to_rendered_pdf_geometry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_docx(tmp_path / "contract.docx", heading="第四条 付款条件", paragraphs=["发票开具后 30 天内付款"])
    rendered = snapshot_with_pdf_lines(["第四条 付款条件", "发票开具后 30 天内付款"])
    monkeypatch.setattr("artifactdiff.formats.docx.PdfAdapter.load", lambda *args, **kwargs: rendered)
    snapshot = DocxAdapter().load(source, render=True, workdir=tmp_path / "work")
    assert snapshot.blocks[1].metadata["rendered_page_index"] == 0
    assert snapshot.blocks[1].metadata["rendered_bbox"] == rendered.blocks[1].bbox.model_dump()
```

- [ ] **Step 2: Implement deterministic logical-to-rendered alignment**

After LibreOffice rendering, align logical blocks to rendered PDF blocks using `align_sequences` with normalized text. Copy page and bounding-box metadata only for one-to-one pairs whose normalized strings are equal or whose `SequenceMatcher.ratio()` is at least `0.98`; leave missing or ambiguous evidence unset and append one bounded warning.

```python
def _link_rendered_evidence(logical: list[ContentBlock], rendered: list[ContentBlock]) -> None:
    pairs = align_sequences(logical, rendered, key=lambda block: block.normalized_text)
    for pair in pairs:
        if pair.before is None or pair.after is None or pair.after.bbox is None:
            continue
        score = SequenceMatcher(None, pair.before.normalized_text, pair.after.normalized_text).ratio()
        if score < 0.98:
            continue
        pair.before.metadata["rendered_page_index"] = pair.after.page_index
        pair.before.metadata["rendered_bbox"] = pair.after.bbox.model_dump(mode="json")
```

- [ ] **Step 3: Write failing selector tests**

```python
def test_baseline_selector_must_resolve_once(contract: ContractDocument) -> None:
    selector = ClauseSelector(clause_label="第四条", heading="付款条件", anchor="30 天内付款", occurrences=1)
    resolution = resolve_baseline(contract, selector)
    assert resolution.status is SelectorResolutionStatus.UNIQUE
    assert resolution.matches[0].clause_id == contract.clauses[3].id


def test_candidate_selector_rejects_tied_matches(ambiguous_contract: ContractDocument) -> None:
    selector = ClauseSelector(clause_label="4.2", heading="Payment", anchor="within 30 days", occurrences=1)
    resolution = resolve_candidate(ambiguous_contract, selector)
    assert resolution.status is SelectorResolutionStatus.AMBIGUOUS
```

- [ ] **Step 4: Implement versioned selector models and scoring**

```python
class ClauseSelector(StrictModel):
    clause_label: str
    heading: str
    ancestor_path: tuple[str, ...] = ()
    anchor: str
    baseline_fingerprint: str = ""
    occurrences: int = Field(default=1, ge=1, le=100)
    matcher_version: Literal["1.0"] = "1.0"
    min_similarity: float = Field(default=0.92, ge=0.0, le=1.0)
    min_margin: float = Field(default=0.05, ge=0.0, le=1.0)


class SelectorResolutionStatus(StrEnum):
    UNIQUE = "unique"
    HIGH_CONFIDENCE = "high_confidence"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
```

Baseline resolution requires exact normalized label, heading, ancestor path, anchor occurrence count, and fingerprint when supplied. Candidate scoring gives fixed weights `0.35` label, `0.25` heading, `0.15` ancestor path, and `0.25` anchor/fingerprint. Mandatory label and ancestor fields must agree; a candidate is high-confidence only when its score is at least `min_similarity` and exceeds the runner-up by `min_margin`. Sort ties by clause ID but return `ambiguous`, never the first tied clause.

- [ ] **Step 5: Run selector, adapter, and analyzer tests**

Run: `python -m pytest tests/unit/contract tests/unit/test_docx_adapter.py -q`

Expected: PASS; exact cross-format selector fixtures resolve and duplicated headings remain ambiguous.

- [ ] **Step 6: Commit selectors and visual evidence links**

```bash
git add src/artifactdiff/contract src/artifactdiff/formats/docx.py tests/unit/contract tests/unit/test_docx_adapter.py
git commit -m "feat: resolve contract clauses across formats"
```

---

### Task 5: Contract inspection service and bounded public result

**Files:**
- Create: `src/artifactdiff/contract/service.py`
- Create: `tests/integration/contract/test_contract_service.py`
- Modify: `tests/factories.py`
- Modify: `src/artifactdiff/contract/__init__.py`

**Interfaces:**
- Consumes: `validate_source`, `adapter_for`, `analyze_contract`
- Produces: `load_contract(path: Path, *, render: bool, force: bool, workdir: Path) -> tuple[DocumentSnapshot, ContractDocument]`
- Produces: `inspect_contract(path: Path, *, force: bool = False, require_absolute: bool = False, max_clauses: int = 100) -> dict[str, object]`

- [ ] **Step 1: Add deterministic contract fixtures**

Add `make_contract_docx` and `make_contract_pdf` helpers that generate the same four-clause contract in Chinese, English, or bilingual form. The payment clause must contain party, money, date, duration, and percentage values; the documents must include a header, footer, signature area, and attachment heading.

```python
def contract_lines(language: str, payment_days: int = 30) -> list[str]:
    if language == "zh":
        return ["合同编号 AD-001", "第一条 合同主体", "甲方：上海示例科技有限公司", "第四条 付款条件", f"发票开具后 {payment_days} 天内付款", "签字盖章"]
    if language == "en":
        return ["Contract AD-001", "Article I Parties", "Party A: Example Ltd.", "Section 4 Payment Terms", f"Payment is due within {payment_days} days", "Signature"]
    return ["合同 Contract AD-001", "第一条 Parties 合同主体", "甲方 Party A: Example Ltd.", "第四条 Payment Terms 付款条件", f"发票后 Payment is due within {payment_days} 天 days", "签字 Signature"]
```

- [ ] **Step 2: Write failing service tests**

```python
def test_inspect_contract_returns_bounded_portable_ir(tmp_path: Path) -> None:
    source = make_contract_docx(tmp_path / "contract.docx", language="zh")
    result = inspect_contract(source, max_clauses=2)
    assert result["language"]["kind"] == "zh"
    assert len(result["clauses"]) == 2
    assert result["truncated_clauses"] is True
    assert json.dumps(result, ensure_ascii=False)


def test_docx_and_pdf_contracts_resolve_the_same_payment_selector(tmp_path: Path) -> None:
    docx = load_contract_fixture(tmp_path, "docx", "zh")
    pdf = load_contract_fixture(tmp_path, "pdf", "zh")
    selector = selector_for_payment_clause(docx)
    assert resolve_candidate(pdf, selector).status is SelectorResolutionStatus.HIGH_CONFIDENCE
```

- [ ] **Step 3: Implement the service with temporary-work isolation**

```python
def load_contract(path: Path, *, render: bool, force: bool, workdir: Path) -> tuple[DocumentSnapshot, ContractDocument]:
    source = validate_source(path, force=force)
    snapshot = adapter_for(source).load(source, render=render, workdir=workdir, force=force)
    return snapshot, analyze_contract(snapshot)


def inspect_contract(path: Path, *, force: bool = False, require_absolute: bool = False, max_clauses: int = 100) -> dict[str, object]:
    if not 0 <= max_clauses <= 1000:
        raise InputValidationError("max_clauses must be between 0 and 1000")
    source = validate_source(path, force=force, require_absolute=require_absolute)
    with TemporaryDirectory(prefix="artifactdiff-contract-") as temporary:
        _, contract = load_contract(source, render=False, force=force, workdir=Path(temporary))
    payload = contract.model_dump(mode="json")
    payload["clauses"] = payload["clauses"][:max_clauses]
    payload["truncated_clauses"] = len(contract.clauses) > max_clauses
    return payload
```

- [ ] **Step 4: Run the complete foundation suite**

Run: `python -m pytest tests/unit/contract tests/integration/contract/test_contract_service.py tests/unit/test_docx_adapter.py tests/unit/test_pdf_adapter.py -q`

Run: `python -m pytest -q`

Expected: all new and all existing tests PASS.

- [ ] **Step 5: Commit the bounded contract service**

```bash
git add src/artifactdiff/contract tests/factories.py tests/integration/contract
git commit -m "feat: expose deterministic contract inspection"
```

---

## Plan 1 completion gate

- [ ] Chinese, English, and bilingual clause fixtures produce stable Contract IR.
- [ ] Entity normalization and IDs are byte-stable across repeated runs.
- [ ] Baseline selectors require one exact resolution.
- [ ] Candidate ambiguity returns `ambiguous` and never selects by order.
- [ ] DOCX render enrichment links exact logical text to page geometry when available.
- [ ] Comments, tracked revisions, hidden text, external links, embedded images, and metadata become deterministic bounded feature facts.
- [ ] DOCX and PDF versions of the same synthetic contract resolve the same payment clause.
- [ ] Existing comparison and report tests still pass without schema changes.
