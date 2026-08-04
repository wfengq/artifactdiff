import pytest

from artifactdiff.contract.analyzer import analyze_contract
from artifactdiff.contract.models import EvidenceRef, ProtectedRegionKind
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot
from artifactdiff.normalize import normalize_text


@pytest.fixture
def snapshot_with_nested_clauses() -> DocumentSnapshot:
    blocks = [
        ContentBlock(
            id="block-1",
            ordinal=0,
            content_type=ContentType.HEADING,
            text="\u7b2c\u56db\u6761 \u4ed8\u6b3e\u6761\u4ef6",
            normalized_text=normalize_text("\u7b2c\u56db\u6761 \u4ed8\u6b3e\u6761\u4ef6"),
        ),
        ContentBlock(
            id="block-2",
            ordinal=1,
            content_type=ContentType.PARAGRAPH,
            text="\uff08\u4e00\uff09\u4ed8\u6b3e\u65f6\u95f4",
            normalized_text=normalize_text("\uff08\u4e00\uff09\u4ed8\u6b3e\u65f6\u95f4"),
        ),
        ContentBlock(
            id="block-3",
            ordinal=2,
            content_type=ContentType.PARAGRAPH,
            text="\u4e59\u65b9\u5e94\u5728 45 \u5929\u5185\u652f\u4ed8 RMB 10,000.00\u3002",
            normalized_text=normalize_text("\u4e59\u65b9\u5e94\u5728 45 \u5929\u5185\u652f\u4ed8 RMB 10,000.00\u3002"),
        ),
        ContentBlock(
            id="block-4",
            ordinal=3,
            content_type=ContentType.PARAGRAPH,
            text="4.2 \u4ed8\u6b3e\u91d1\u989d",
            normalized_text=normalize_text("4.2 \u4ed8\u6b3e\u91d1\u989d"),
        ),
    ]
    return DocumentSnapshot(
        source_path="contract.docx",
        format="docx",
        sha256="a" * 64,
        size_bytes=1,
        blocks=blocks,
    )


def test_analyzer_builds_parent_child_hierarchy(
    snapshot_with_nested_clauses: DocumentSnapshot,
) -> None:
    contract = analyze_contract(snapshot_with_nested_clauses)

    assert [clause.label.printed for clause in contract.clauses] == ["\u7b2c\u56db\u6761", "\uff08\u4e00\uff09", "4.2"]
    assert contract.clauses[1].parent_id == contract.clauses[0].id
    assert contract.clauses[1].ancestor_path == ("\u4ed8\u6b3e\u6761\u4ef6",)
    assert contract.clauses[1].id in contract.clauses[0].child_ids
    assert contract.clauses[1].entities[0].evidence == [EvidenceRef(block_id="block-3")]


def test_analyzer_preserves_tables_and_classifies_anchored_protected_regions() -> None:
    blocks = [
        ContentBlock(id="body", ordinal=1, content_type=ContentType.PARAGRAPH, text="Preface", normalized_text="preface"),
        ContentBlock(id="heading", ordinal=2, content_type=ContentType.HEADING, text="Section 1 Terms", normalized_text="section 1 terms"),
        ContentBlock(id="table", ordinal=3, content_type=ContentType.TABLE, text="RMB 100", normalized_text="rmb 100"),
        ContentBlock(id="signature", ordinal=4, content_type=ContentType.PARAGRAPH, text="\u7b7e\u5b57\uff1aAlice", normalized_text="\u7b7e\u5b57\uff1aalice"),
        ContentBlock(id="header", ordinal=5, content_type=ContentType.HEADER, text="Confidential", normalized_text="confidential"),
        ContentBlock(id="footer", ordinal=6, content_type=ContentType.FOOTER, text="Page 1", normalized_text="page 1"),
        ContentBlock(id="attachment", ordinal=7, content_type=ContentType.PARAGRAPH, text="Attachment A", normalized_text="attachment a"),
    ]
    snapshot = DocumentSnapshot(
        source_path="contract.pdf", format="pdf", sha256="b" * 64, size_bytes=2, blocks=blocks
    )

    contract = analyze_contract(snapshot)

    assert [evidence.block_id for evidence in contract.tables] == ["table"]
    assert "RMB 100" in contract.clauses[-1].text
    assert [region.kind for region in contract.protected_regions] == [
        ProtectedRegionKind.SIGNATURE,
        ProtectedRegionKind.HEADER,
        ProtectedRegionKind.FOOTER,
        ProtectedRegionKind.ATTACHMENT,
    ]


def test_analyzer_disambiguates_duplicate_base_ids_using_full_clause_text() -> None:
    long_prefix = "x" * 180
    blocks = [
        ContentBlock(
            id="heading-1",
            ordinal=0,
            content_type=ContentType.HEADING,
            text="Section 1 Shared heading",
            normalized_text="section 1 shared heading",
        ),
        ContentBlock(
            id="body-1",
            ordinal=1,
            content_type=ContentType.PARAGRAPH,
            text=f"{long_prefix} first ending RMB 100",
            normalized_text=normalize_text(f"{long_prefix} first ending RMB 100"),
        ),
        ContentBlock(
            id="heading-2",
            ordinal=2,
            content_type=ContentType.HEADING,
            text="Section 1 Shared heading",
            normalized_text="section 1 shared heading",
        ),
        ContentBlock(
            id="body-2",
            ordinal=3,
            content_type=ContentType.PARAGRAPH,
            text=f"{long_prefix} second ending RMB 200",
            normalized_text=normalize_text(f"{long_prefix} second ending RMB 200"),
        ),
    ]
    snapshot = DocumentSnapshot(
        source_path="contract.docx", format="docx", sha256="c" * 64, size_bytes=3, blocks=blocks
    )

    first = analyze_contract(snapshot)
    second = analyze_contract(snapshot)

    assert len({clause.id for clause in first.clauses}) == 2
    assert [clause.id for clause in second.clauses] == [clause.id for clause in first.clauses]
    assert all(
        entity.clause_id == clause.id
        for clause in first.clauses
        for entity in clause.entities
    )
