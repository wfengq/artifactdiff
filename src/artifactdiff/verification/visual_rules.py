"""Deterministic, content-free helpers for contract visual policy."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from itertools import pairwise

from artifactdiff.contract.models import EvidenceRef
from artifactdiff.models import Rect
from artifactdiff.policy import VisualPolicy
from artifactdiff.verification.models import (
    Finding,
    FindingEvidence,
    FindingOutcome,
    finding_id,
)

MAX_UNION_CONTAINMENT_BOXES = 128


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


def union_rectangles(rectangles: Iterable[Rect]) -> tuple[Rect, ...]:
    """Return a deterministic, discrete union without filling gaps between boxes."""
    return tuple(sorted(rectangles, key=lambda item: (item.x0, item.y0, item.x1, item.y1)))


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


def _union_contains_rectangle(changed: Rect, boxes: Sequence[Rect], padding: float) -> bool:
    """Check exact rectangle coverage by a bounded union of axis-aligned boxes."""
    if changed.x0 >= changed.x1 or changed.y0 >= changed.y1:
        return False
    if len(boxes) > MAX_UNION_CONTAINMENT_BOXES:
        return False
    expanded = [expand_rect(box, padding) for box in boxes]
    relevant = [
        box
        for box in expanded
        if box.x0 < changed.x1
        and box.x1 > changed.x0
        and box.y0 < changed.y1
        and box.y1 > changed.y0
    ]
    x_boundaries = {changed.x0, changed.x1}
    for box in relevant:
        x_boundaries.add(max(changed.x0, box.x0))
        x_boundaries.add(min(changed.x1, box.x1))
    ordered_x = sorted(x_boundaries)
    for left, right in pairwise(ordered_x):
        intervals = sorted(
            (box.y0, box.y1) for box in relevant if box.x0 <= left and right <= box.x1
        )
        covered_until = changed.y0
        for bottom, top in intervals:
            if bottom > covered_until:
                return False
            covered_until = max(covered_until, top)
            if covered_until >= changed.y1:
                break
        if covered_until < changed.y1:
            return False
    return True


def assess_visual_change(
    *,
    expected_box: Rect | None,
    expected_boxes: Sequence[Rect] | None = None,
    changed: Rect,
    padding: float,
    protected_boxes: list[Rect] | None = None,
    location: str = "visual:page:unscoped",
    locations: Sequence[EvidenceRef] = (),
) -> Finding:
    """Assess one changed box against an expected envelope and protected boxes."""
    boxes = (
        tuple(expected_boxes)
        if expected_boxes is not None
        else ((expected_box,) if expected_box else ())
    )
    expected_fingerprint = _fingerprint([_rect_payload(box) for box in boxes]) if boxes else None
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
    if _union_contains_rectangle(changed, boxes, padding):
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
