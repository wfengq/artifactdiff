"""Deterministic, content-free helpers for contract visual policy."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence

from artifactdiff.contract.models import EvidenceRef
from artifactdiff.models import Rect
from artifactdiff.policy import VisualPolicy
from artifactdiff.verification.models import (
    Finding,
    FindingEvidence,
    FindingOutcome,
    finding_id,
)


def _rect_payload(rect: Rect) -> list[float]:
    return [rect.x0, rect.y0, rect.x1, rect.y1]


def _fingerprint(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _finding(
    *,
    rule_id: str,
    outcome: FindingOutcome,
    location: str,
    before_fingerprint: str | None,
    after_fingerprint: str | None,
    remediation: str,
    approvable: bool = False,
    locations: Sequence[EvidenceRef] = (),
) -> Finding:
    identifier = finding_id(
        rule_id=rule_id,
        rule_version="1.0",
        location=location,
        before_fingerprint=before_fingerprint,
        after_fingerprint=after_fingerprint,
    )
    return Finding(
        id=identifier,
        rule_id=rule_id,
        outcome=outcome,
        location=location,
        evidence=FindingEvidence(
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            locations=list(locations),
        ),
        remediation=remediation,
        approvable=approvable,
    )


def expand_rect(rect: Rect, padding: float) -> Rect:
    """Expand one rendered box by an exact number of points."""
    if isinstance(padding, bool) or not isinstance(padding, (int, float)) or padding < 0:
        raise ValueError("padding must be a non-negative number")
    return Rect(
        x0=rect.x0 - padding,
        y0=rect.y0 - padding,
        x1=rect.x1 + padding,
        y1=rect.y1 + padding,
    )


def union_rectangles(rectangles: Iterable[Rect]) -> Rect | None:
    """Return the smallest rectangle containing every supplied box."""
    items = list(rectangles)
    if not items:
        return None
    return Rect(
        x0=min(item.x0 for item in items),
        y0=min(item.y0 for item in items),
        x1=max(item.x1 for item in items),
        y1=max(item.y1 for item in items),
    )


def rect_contains(container: Rect, contained: Rect) -> bool:
    return (
        container.x0 <= contained.x0
        and container.y0 <= contained.y0
        and container.x1 >= contained.x1
        and container.y1 >= contained.y1
    )


def rects_overlap(left: Rect, right: Rect) -> bool:
    return max(left.x0, right.x0) < min(left.x1, right.x1) and max(left.y0, right.y0) < min(
        left.y1, right.y1
    )


def assess_visual_change(
    *,
    expected_box: Rect | None,
    changed: Rect,
    padding: float,
    protected_boxes: list[Rect] | None = None,
    location: str = "visual:page:unscoped",
    locations: Sequence[EvidenceRef] = (),
) -> Finding:
    """Assess one changed box against an expected envelope and protected boxes."""
    expected_fingerprint = (
        _fingerprint(_rect_payload(expected_box)) if expected_box is not None else None
    )
    changed_fingerprint = _fingerprint(_rect_payload(changed))
    if any(rects_overlap(changed, protected) for protected in protected_boxes or []):
        return _finding(
            rule_id="contract-safe.visual.protected",
            outcome=FindingOutcome.FAIL,
            location=location,
            before_fingerprint=expected_fingerprint,
            after_fingerprint=changed_fingerprint,
            remediation="Restore the protected rendered region.",
            locations=locations,
        )
    if expected_box is not None and rect_contains(expand_rect(expected_box, padding), changed):
        return _finding(
            rule_id="contract-safe.visual.explained",
            outcome=FindingOutcome.PASS,
            location=location,
            before_fingerprint=expected_fingerprint,
            after_fingerprint=changed_fingerprint,
            remediation="No action required.",
            locations=locations,
        )
    return _finding(
        rule_id="contract-safe.visual.outside-envelope",
        outcome=FindingOutcome.REVIEW,
        location=location,
        before_fingerprint=expected_fingerprint,
        after_fingerprint=changed_fingerprint,
        remediation="Review the rendered change outside the expected edit envelope.",
        approvable=True,
        locations=locations,
    )


def assess_pagination_reflow(
    *,
    policy: VisualPolicy,
    location: str = "visual:pagination",
    locations: Sequence[EvidenceRef] = (),
) -> Finding:
    outcome = FindingOutcome(policy.pagination_reflow)
    return _finding(
        rule_id="contract-safe.visual.pagination-reflow",
        outcome=outcome,
        location=location,
        before_fingerprint=None,
        after_fingerprint=None,
        remediation="Review pagination and page pairing."
        if outcome is FindingOutcome.REVIEW
        else "Restore the original pagination.",
        approvable=outcome is FindingOutcome.REVIEW,
        locations=locations,
    )


def assess_page_deletion(
    *, location: str = "visual:page-deletion", locations: Sequence[EvidenceRef] = ()
) -> Finding:
    """Fail closed when a baseline page has no corresponding candidate page."""
    return _finding(
        rule_id="contract-safe.visual.page-deletion",
        outcome=FindingOutcome.FAIL,
        location=location,
        before_fingerprint=None,
        after_fingerprint=None,
        remediation="Restore the deleted baseline page.",
        locations=locations,
    )


def assess_protected_region_change(
    *, policy: VisualPolicy, location: str = "visual:protected-region"
) -> Finding:
    return _finding(
        rule_id="contract-safe.visual.protected",
        outcome=FindingOutcome(policy.protected_region_change),
        location=location,
        before_fingerprint=None,
        after_fingerprint=None,
        remediation="Restore the protected rendered region.",
    )


def assess_visual_availability(*, policy: VisualPolicy, available: bool) -> Finding | None:
    if available:
        return None
    outcome = FindingOutcome(policy.on_unavailable)
    return _finding(
        rule_id="contract-safe.visual.unavailable",
        outcome=outcome,
        location="visual:unavailable",
        before_fingerprint=None,
        after_fingerprint=None,
        remediation="Provide renderable visual evidence.",
        approvable=outcome is FindingOutcome.REVIEW,
    )
