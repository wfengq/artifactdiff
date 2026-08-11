import pytest

from artifactdiff.verification.alignment import (
    AlignmentBudget,
    OccurrenceAnchor,
    TextSpan,
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
