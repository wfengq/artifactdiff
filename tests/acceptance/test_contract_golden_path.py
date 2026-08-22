from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifactdiff.errors import ApprovalError
from artifactdiff.verification import FindingOutcome
from scripts.run_contract_golden_path import run_golden_path


def test_verified_contract_golden_path_covers_pass_review_and_fail(tmp_path: Path) -> None:
    """The flagship demo must prove the complete signed contract-review lifecycle."""
    result = run_golden_path(tmp_path / "golden-path", approve_review=True)

    assert set(result.cases) == {"authorized", "review", "unauthorized"}

    authorized = result.cases["authorized"]
    assert authorized.raw_outcome is FindingOutcome.PASS
    assert authorized.effective_outcome is FindingOutcome.PASS
    assert authorized.assurance == "verified"
    assert authorized.bundle_valid is True
    assert authorized.signature_valid_at_creation is True
    assert authorized.currently_trusted is True

    review = result.cases["review"]
    assert review.raw_outcome is FindingOutcome.REVIEW
    assert review.preapproval_outcome is FindingOutcome.REVIEW
    assert review.effective_outcome is FindingOutcome.PASS
    assert review.approved_finding_ids
    assert review.bundle_valid is True
    assert review.event_chain_valid is True

    unauthorized = result.cases["unauthorized"]
    assert unauthorized.raw_outcome is FindingOutcome.FAIL
    assert unauthorized.effective_outcome is FindingOutcome.FAIL
    assert unauthorized.nonapprovable_finding_ids
    assert unauthorized.bundle_valid is True

    with pytest.raises(ApprovalError, match="fail findings cannot be approved"):
        result.attempt_unauthorized_approval()

    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert summary["privacy"] == "synthetic-data-only; private signing keys were not persisted"
    assert {name: payload["effective_outcome"] for name, payload in summary["cases"].items()} == {
        "authorized": "pass",
        "review": "pass",
        "unauthorized": "fail",
    }
    assert not any(path.suffix.casefold() in {".key", ".pem"} for path in result.root.rglob("*"))


def test_golden_path_leaves_review_blocking_without_explicit_approval(tmp_path: Path) -> None:
    """The demo must not silently turn a review finding into a pass."""
    result = run_golden_path(tmp_path / "golden-path", approve_review=False)

    review = result.cases["review"]
    assert review.preapproval_outcome is FindingOutcome.REVIEW
    assert review.effective_outcome is FindingOutcome.REVIEW
    assert review.approved_finding_ids == ()
    assert review.bundle_valid is True
