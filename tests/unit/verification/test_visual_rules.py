from __future__ import annotations

import pytest

from artifactdiff.models import Rect
from artifactdiff.policy import VisualPolicy
from artifactdiff.verification import FindingOutcome
from artifactdiff.verification.visual_rules import (
    assess_pagination_reflow,
    assess_protected_region_change,
    assess_visual_availability,
    assess_visual_change,
)


def test_visual_delta_inside_exactly_padded_expected_box_passes() -> None:
    finding = assess_visual_change(
        expected_box=Rect(x0=10, y0=10, x1=80, y1=30),
        changed=Rect(x0=4, y0=4, x1=86, y1=36),
        padding=6,
    )

    assert finding.outcome is FindingOutcome.PASS
    assert finding.approvable is False


def test_visual_delta_beyond_expected_box_reviews_approvably() -> None:
    finding = assess_visual_change(
        expected_box=Rect(x0=10, y0=10, x1=80, y1=30),
        changed=Rect(x0=3.999, y0=4, x1=86, y1=36),
        padding=6,
    )

    assert finding.outcome is FindingOutcome.REVIEW
    assert finding.approvable is True


@pytest.mark.parametrize(
    ("boxes", "changed"),
    [
        (
            [
                Rect(x0=10, y0=10, x1=20, y1=20),
                Rect(x0=20, y0=10, x1=30, y1=20),
            ],
            Rect(x0=15, y0=10, x1=25, y1=20),
        ),
        (
            [
                Rect(x0=10, y0=10, x1=22, y1=20),
                Rect(x0=18, y0=10, x1=30, y1=20),
            ],
            Rect(x0=15, y0=10, x1=25, y1=20),
        ),
    ],
)
def test_visual_delta_covered_by_combined_boxes_passes_as_their_union(
    boxes: list[Rect], changed: Rect
) -> None:
    finding = assess_visual_change(
        expected_box=None,
        expected_boxes=boxes,
        changed=changed,
        padding=0,
    )

    assert finding.outcome is FindingOutcome.PASS
    assert finding.approvable is False


def test_visual_delta_crossing_an_uncovered_gap_reviews() -> None:
    finding = assess_visual_change(
        expected_box=None,
        expected_boxes=[
            Rect(x0=10, y0=10, x1=20, y1=20),
            Rect(x0=30, y0=10, x1=40, y1=20),
        ],
        changed=Rect(x0=15, y0=10, x1=35, y1=20),
        padding=0,
    )

    assert finding.outcome is FindingOutcome.REVIEW
    assert finding.approvable is True


def test_protected_overlap_takes_precedence_over_explained_envelope() -> None:
    finding = assess_visual_change(
        expected_box=None,
        expected_boxes=[
            Rect(x0=10, y0=10, x1=20, y1=20),
            Rect(x0=20, y0=10, x1=30, y1=20),
        ],
        changed=Rect(x0=12, y0=12, x1=20, y1=20),
        padding=6,
        protected_boxes=[Rect(x0=15, y0=15, x1=25, y1=25)],
    )

    assert finding.outcome is FindingOutcome.FAIL
    assert finding.approvable is False


def test_pagination_and_protected_region_follow_visual_policy() -> None:
    assert assess_pagination_reflow(policy=VisualPolicy()).outcome is FindingOutcome.REVIEW
    assert (
        assess_pagination_reflow(policy=VisualPolicy(pagination_reflow="fail")).outcome
        is FindingOutcome.FAIL
    )
    assert assess_protected_region_change(policy=VisualPolicy()).outcome is FindingOutcome.FAIL


def test_missing_visual_evidence_reviews_by_default_and_never_passes() -> None:
    default = assess_visual_availability(policy=VisualPolicy(), available=False)
    strict = assess_visual_availability(policy=VisualPolicy(on_unavailable="fail"), available=False)

    assert (default.outcome, default.approvable) == (FindingOutcome.REVIEW, True)
    assert (strict.outcome, strict.approvable) == (FindingOutcome.FAIL, False)
    assert assess_visual_availability(policy=VisualPolicy(), available=True) is None
