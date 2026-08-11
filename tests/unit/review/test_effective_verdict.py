from __future__ import annotations

import pytest

from artifactdiff.review import EffectiveVerdict
from artifactdiff.verification import FindingOutcome


def test_effective_verdict_rejects_overlapping_finding_sets() -> None:
    with pytest.raises(ValueError):
        EffectiveVerdict(
            raw_outcome=FindingOutcome.REVIEW,
            outcome=FindingOutcome.PASS,
            approved_finding_ids=["finding-a"],
            remaining_review_finding_ids=["finding-a"],
            fail_finding_ids=[],
            event_chain_head="a" * 64,
        )
