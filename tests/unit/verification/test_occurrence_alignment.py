import pytest

from artifactdiff.verification.alignment import (
    AlignmentBudget,
    OccurrenceAnchor,
    TextSpan,
    is_unambiguous_pure_replacement,
    prove_atomic_occurrence_alignment,
)


def _span(text: str, value: str, *, start: int = 0) -> TextSpan:
    index = text.index(value, start)
    return TextSpan(start=index, end=index + len(value))


def test_correct_anchor_is_required_by_every_optimal_path() -> None:
    before = "Payment: RED; fee unchanged."
    after = "Payment: BLUE; fee revised."

    assert prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "RED"), _span(after, "BLUE")),),
        AlignmentBudget(),
    )


def test_distant_near_collision_is_not_a_proven_anchor() -> None:
    before = "First: RED\nSecond: RDX"
    after = "First: GREEN\nSecond: BLUE"

    assert not prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "RED"), _span(after, "BLUE")),),
        AlignmentBudget(),
    )


def test_budget_exhaustion_fails_closed_without_overspending() -> None:
    budget = AlignmentBudget(remaining_cells=8)
    before = "A RED B"
    after = "A BLUE B"

    assert not prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "RED"), _span(after, "BLUE")),),
        budget,
    )
    assert budget.remaining_cells == 8


@pytest.mark.parametrize(
    "anchors",
    [
        (OccurrenceAnchor(TextSpan(2, 2), TextSpan(2, 3)),),
        (OccurrenceAnchor(TextSpan(2, 99), TextSpan(2, 3)),),
        (
            OccurrenceAnchor(TextSpan(0, 2), TextSpan(0, 2)),
            OccurrenceAnchor(TextSpan(1, 3), TextSpan(3, 5)),
        ),
        (
            OccurrenceAnchor(TextSpan(0, 1), TextSpan(4, 5)),
            OccurrenceAnchor(TextSpan(4, 5), TextSpan(0, 1)),
        ),
    ],
    ids=["empty", "out-of-range", "overlap", "candidate-order"],
)
def test_invalid_anchor_geometry_fails_closed(
    anchors: tuple[OccurrenceAnchor, ...],
) -> None:
    assert not prove_atomic_occurrence_alignment(
        "RED X BLUE",
        "RED X BLUE",
        anchors,
        AlignmentBudget(),
    )


def test_two_ordered_anchors_are_proven_together() -> None:
    before = "Pay USD within 30 days."
    after = "Pay EUR within 45 days."
    usd = _span(before, "USD")
    days_30 = _span(before, "30")
    eur = _span(after, "EUR")
    days_45 = _span(after, "45")

    assert prove_atomic_occurrence_alignment(
        before,
        after,
        (
            OccurrenceAnchor(usd, eur),
            OccurrenceAnchor(days_30, days_45),
        ),
        AlignmentBudget(),
    )


def test_nfc_text_alignment_is_deterministic() -> None:
    before = "付款期限：三十天；名称：Café。"
    after = "付款期限：四十五天；名称：Café。"

    first = prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "三十天"), _span(after, "四十五天")),),
        AlignmentBudget(),
    )
    second = prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "三十天"), _span(after, "四十五天")),),
        AlignmentBudget(),
    )

    assert first is True
    assert second is first



def _all_spans(text: str, value: str) -> list[TextSpan]:
    spans: list[TextSpan] = []
    start = text.find(value)
    while start >= 0:
        spans.append(TextSpan(start=start, end=start + len(value)))
        start = text.find(value, start + len(value))
    return spans


def _pure_replacement_cases() -> list[tuple[str, str, str, str, int]]:
    """Seeded random clauses whose candidate is exactly the declared replacement."""
    import random

    rng = random.Random(20261008)
    cases: list[tuple[str, str, str, str, int]] = []
    while len(cases) < 3000:
        alphabet = rng.choice(["ab", "abc", "ab ", "红绿 ", "abcd"])
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(3, 40)))
        start = rng.randrange(len(text))
        before_value = text[start : start + rng.randint(1, 5)]
        after_value = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 5)))
        occurrences = text.count(before_value)
        if not before_value or before_value == after_value or occurrences > 3:
            continue
        after_text = text.replace(before_value, after_value, occurrences)
        if after_text.count(after_value) != occurrences or before_value in after_text:
            continue
        cases.append((text, after_text, before_value, after_value, occurrences))
    return cases


def test_unambiguous_pure_replacement_implies_alignment_proof() -> None:
    """The shortcut may only skip alignment where alignment would prove the mapping."""
    shortcut_taken = 0
    for before_text, after_text, before_value, after_value, occurrences in (
        _pure_replacement_cases()
    ):
        before_spans = _all_spans(before_text, before_value)
        after_spans = _all_spans(after_text, after_value)
        if len(before_spans) != occurrences or len(after_spans) != occurrences:
            continue
        anchors = tuple(
            OccurrenceAnchor(before=b, after=a)
            for b, a in zip(before_spans, after_spans, strict=True)
        )
        if is_unambiguous_pure_replacement(
            before_text, after_text, anchors, before_value, after_value
        ):
            shortcut_taken += 1
            assert prove_atomic_occurrence_alignment(
                before_text, after_text, anchors, AlignmentBudget()
            ), (before_text, after_text, before_value, after_value)
    assert shortcut_taken > 2000


def test_overlapping_replacement_position_is_not_a_pure_shortcut() -> None:
    before_text, after_text = "babbbaa", "babbbbb"
    anchors = (OccurrenceAnchor(_span(before_text, "baa"), _span(after_text, "bbb")),)
    assert not is_unambiguous_pure_replacement(before_text, after_text, anchors, "baa", "bbb")
    assert not prove_atomic_occurrence_alignment(
        before_text, after_text, anchors, AlignmentBudget()
    )


def test_pure_shortcut_rejects_any_extra_change() -> None:
    before_text = "Payment: RED; fee unchanged."
    after_text = "Payment: BLUE; fee revised."
    anchors = (OccurrenceAnchor(_span(before_text, "RED"), _span(after_text, "BLUE")),)
    assert not is_unambiguous_pure_replacement(before_text, after_text, anchors, "RED", "BLUE")
