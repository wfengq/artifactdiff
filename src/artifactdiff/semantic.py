"""Semantic change classification for document snapshots."""

from collections import Counter
from typing import Literal

from artifactdiff.alignment import AlignedPair, align_sequences
from artifactdiff.models import BlockRef, ContentBlock, DocumentSnapshot, SemanticChange
from artifactdiff.normalize import normalize_text


def diff_snapshots(before: DocumentSnapshot, after: DocumentSnapshot) -> list[SemanticChange]:
    """Return deterministic semantic changes between two document snapshots."""
    pairs = align_sequences(
        before.blocks,
        after.blocks,
        key=lambda block: f"{block.content_type}:{normalize_text(block.normalized_text)}",
    )
    changes = [_change_from_pair(pair) for pair in pairs if not _pair_is_unchanged(pair)]
    return _promote_exact_moves(changes)


def _pair_is_unchanged(pair: AlignedPair[ContentBlock]) -> bool:
    return (
        pair.before is not None
        and pair.after is not None
        and pair.before.content_type == pair.after.content_type
        and normalize_text(pair.before.normalized_text) == normalize_text(pair.after.normalized_text)
    )


def _change_from_pair(pair: AlignedPair[ContentBlock]) -> SemanticChange:
    before = pair.before
    after = pair.after
    kind: Literal["added", "removed", "modified"]
    if before is None:
        assert after is not None
        kind = "added"
        content_type = after.content_type
    elif after is None:
        kind = "removed"
        content_type = before.content_type
    else:
        kind = "modified"
        content_type = after.content_type

    return SemanticChange(
        id=f"semantic-{before.id if before is not None else 'none'}-{after.id if after is not None else 'none'}",
        kind=kind,
        content_type=content_type,
        similarity=pair.similarity,
        before=_block_ref(before) if before is not None else None,
        after=_block_ref(after) if after is not None else None,
    )


def _block_ref(block: ContentBlock) -> BlockRef:
    return BlockRef(
        block_id=block.id,
        ordinal=block.ordinal,
        page_index=block.page_index,
        text=block.text,
    )


def _promote_exact_moves(changes: list[SemanticChange]) -> list[SemanticChange]:
    removed = [change for change in changes if change.kind == "removed"]
    added = [change for change in changes if change.kind == "added"]
    removed_counts = Counter(
        key for change in removed if (key := _change_key(change)) is not None
    )
    added_counts = Counter(
        key for change in added if (key := _change_key(change)) is not None
    )
    unique_keys = {
        key for key, count in removed_counts.items() if count == 1 and added_counts[key] == 1
    }
    added_by_key = {
        key: change
        for change in added
        if (key := _change_key(change)) in unique_keys
    }
    moved_by_removed_id = {
        change.id: added_by_key[key]
        for change in removed
        if (key := _change_key(change)) in unique_keys
    }
    moved_added_ids = {change.id for change in moved_by_removed_id.values()}

    promoted: list[SemanticChange] = []
    for change in changes:
        if change.kind == "added" and change.id in moved_added_ids:
            continue
        if change.id in moved_by_removed_id:
            added_change = moved_by_removed_id[change.id]
            assert change.before is not None and added_change.after is not None
            promoted.append(
                SemanticChange(
                    id=f"semantic-{change.before.block_id}-{added_change.after.block_id}",
                    kind="moved",
                    content_type=change.content_type,
                    similarity=1.0,
                    before=change.before,
                    after=added_change.after,
                )
            )
        else:
            promoted.append(change)
    return promoted

def _change_key(change: SemanticChange) -> tuple[str, str] | None:
    reference = change.before if change.before is not None else change.after
    if reference is None or change.kind not in {"added", "removed"}:
        return None
    return (str(change.content_type), normalize_text(reference.text))
