from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot
from artifactdiff.semantic import diff_snapshots


def block(ordinal: int, text: str) -> ContentBlock:
    return ContentBlock(
        id=f"b{ordinal}",
        ordinal=ordinal,
        content_type=ContentType.PARAGRAPH,
        text=text,
        normalized_text=text.casefold(),
        metadata={},
    )


def snapshot(name: str, blocks: list[ContentBlock]) -> DocumentSnapshot:
    return DocumentSnapshot(
        source_path=f"{name}.docx",
        format="docx",
        sha256=name * 64,
        size_bytes=1,
        blocks=blocks,
    )


def test_semantic_diff_classifies_modified_block() -> None:
    changes = diff_snapshots(
        snapshot("a", [block(0, "Old total")]),
        snapshot("b", [block(0, "New total")]),
    )

    assert len(changes) == 1
    assert changes[0].kind == "modified"
    assert changes[0].before is not None
    assert changes[0].after is not None
    assert changes[0].before.text == "Old total"
    assert changes[0].after.text == "New total"


def test_semantic_diff_classifies_replacement_with_matching_content_type() -> None:
    changes = diff_snapshots(
        snapshot("a", [block(0, "xy")]),
        snapshot("b", [block(0, "1234")]),
    )

    assert [(change.kind, change.before is None, change.after is None) for change in changes] == [
        ("modified", False, False),
    ]


def test_semantic_diff_promotes_a_unique_exact_relocation_to_moved() -> None:
    changes = diff_snapshots(
        snapshot("a", [block(0, "First"), block(1, "Second")]),
        snapshot("b", [block(0, "Second"), block(1, "First")]),
    )

    assert [(change.kind, change.before.text, change.after.text) for change in changes] == [
        ("moved", "Second", "Second"),
    ]


def test_semantic_diff_keeps_duplicate_removals_as_removed_changes() -> None:
    changes = diff_snapshots(
        snapshot("a", [block(0, "Duplicate"), block(1, "Duplicate")]),
        snapshot("b", []),
    )

    assert [(change.kind, change.before.text, change.after) for change in changes] == [
        ("removed", "Duplicate", None),
        ("removed", "Duplicate", None),
    ]


def test_semantic_diff_keeps_duplicate_additions_as_added_changes() -> None:
    changes = diff_snapshots(
        snapshot("a", []),
        snapshot("b", [block(0, "Duplicate"), block(1, "Duplicate")]),
    )

    assert [(change.kind, change.before, change.after.text) for change in changes] == [
        ("added", None, "Duplicate"),
        ("added", None, "Duplicate"),
    ]
