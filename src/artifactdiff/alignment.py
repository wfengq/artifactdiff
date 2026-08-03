"""Deterministic alignment for logical document sequences."""

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Callable, Generic, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class AlignedPair(Generic[T]):
    """A before/after pairing with its text similarity."""

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
    """Align exact sequence anchors and deterministic similar replacements."""
    matcher = SequenceMatcher(
        a=[key(item) for item in before],
        b=[key(item) for item in after],
        autojunk=False,
    )
    pairs: list[AlignedPair[T]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            pairs.extend(
                AlignedPair(left, right, 1.0)
                for left, right in zip(before[i1:i2], after[j1:j2], strict=True)
            )
        elif tag == "delete":
            pairs.extend(AlignedPair(item, None, 0.0) for item in before[i1:i2])
        elif tag == "insert":
            pairs.extend(AlignedPair(None, item, 0.0) for item in after[j1:j2])
        else:
            pairs.extend(_pair_replacements(before[i1:i2], after[j1:j2], key, threshold))
    return pairs


def _pair_replacements(
    before: Sequence[T],
    after: Sequence[T],
    key: Callable[[T], str],
    threshold: float,
) -> list[AlignedPair[T]]:
    candidates = [
        (
            SequenceMatcher(a=key(left), b=key(right), autojunk=False).ratio(),
            before_index,
            after_index,
        )
        for before_index, left in enumerate(before)
        for after_index, right in enumerate(after)
    ]
    candidates.sort(key=lambda candidate: (-candidate[0], candidate[1], candidate[2]))

    used_before: set[int] = set()
    used_after: set[int] = set()
    pairs: list[AlignedPair[T]] = []
    for similarity, before_index, after_index in candidates:
        if similarity < threshold or before_index in used_before or after_index in used_after:
            continue
        used_before.add(before_index)
        used_after.add(after_index)
        pairs.append(AlignedPair(before[before_index], after[after_index], similarity))

    pairs.extend(AlignedPair(item, None, 0.0) for index, item in enumerate(before) if index not in used_before)
    pairs.extend(AlignedPair(None, item, 0.0) for index, item in enumerate(after) if index not in used_after)
    return pairs
