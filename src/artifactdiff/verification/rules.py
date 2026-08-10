"""Deterministic contract-safe policy evaluation without I/O or model calls."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, replace
from itertools import pairwise

from pydantic import ValidationError

from artifactdiff.contract import (
    ClauseSelector,
    ContractClause,
    ContractDocument,
    EntityKind,
    SelectorResolutionStatus,
    resolve_baseline,
    resolve_candidate,
)
from artifactdiff.contract.models import DocumentFeature, EvidenceRef
from artifactdiff.models import Rect, VisualPageChange
from artifactdiff.normalize import normalize_text
from artifactdiff.policy import FrozenPolicy, ProtectedTarget, policy_digest
from artifactdiff.verification.facts import diff_contracts
from artifactdiff.verification.models import (
    MAX_VERDICT_FINDINGS,
    ClauseChange,
    ContractChangeSet,
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
    finding_id,
)
from artifactdiff.verification.visual_rules import (
    assess_page_deletion,
    assess_pagination_reflow,
    assess_visual_availability,
    assess_visual_change,
    rects_overlap,
    union_rectangles,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENTITY_TARGET = {
    EntityKind.PARTY: ProtectedTarget.PARTIES,
    EntityKind.MONEY: ProtectedTarget.MONEY,
    EntityKind.CURRENCY: ProtectedTarget.CURRENCY,
    EntityKind.DATE: ProtectedTarget.DATES,
    EntityKind.DURATION: ProtectedTarget.DURATIONS,
    EntityKind.PERCENTAGE: ProtectedTarget.PERCENTAGES,
}
_REGION_TARGET = {
    "header": ProtectedTarget.HEADERS,
    "footer": ProtectedTarget.FOOTERS,
    "signature": ProtectedTarget.SIGNATURES,
    "seal": ProtectedTarget.SEALS,
    "attachment": ProtectedTarget.ATTACHMENTS,
}


@dataclass(frozen=True, slots=True)
class _Span:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class _ExpectedAssessment:
    rule_id: str
    before_clause: ContractClause
    after_clause: ContractClause
    before_spans: tuple[_Span, ...]
    after_spans: tuple[_Span, ...]
    after_value: str
    corresponds: bool
    applied: bool
    exact: bool


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _safe_sha(value: object) -> str:
    if isinstance(value, str) and _SHA256.fullmatch(value):
        return value
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def _clause_location(before: ContractClause | None, after: ContractClause | None) -> str:
    clause = before if before is not None else after
    if clause is None:
        return "clause:unknown"
    identity = [
        normalize_text(clause.label.normalized),
        [normalize_text(item) for item in clause.ancestor_path],
        normalize_text(clause.heading),
    ]
    return f"clause:{_digest(identity)[:24]}"


def _make_finding(
    *,
    rule_id: str,
    outcome: FindingOutcome,
    location: str,
    before_fingerprint: str | None = None,
    after_fingerprint: str | None = None,
    selector_status: SelectorResolutionStatus | None = None,
    remediation: str,
    approvable: bool = False,
    locations: Sequence[EvidenceRef] = (),
) -> Finding:
    return Finding(
        id=finding_id(
            rule_id=rule_id,
            rule_version="1.0",
            location=location,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
        ),
        rule_id=rule_id,
        outcome=outcome,
        location=location,
        selector_status=selector_status,
        evidence=FindingEvidence(
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            locations=_stable_locations(locations),
        ),
        remediation=remediation,
        approvable=approvable,
    )


def _stable_locations(locations: Sequence[EvidenceRef]) -> list[EvidenceRef]:
    unique = {_canonical(location.model_dump(mode="json")): location for location in locations}
    return [unique[key] for key in sorted(unique)][:32]


def _combine(findings: list[Finding]) -> FindingOutcome:
    if any(item.outcome is FindingOutcome.FAIL for item in findings):
        return FindingOutcome.FAIL
    if any(item.outcome is FindingOutcome.REVIEW for item in findings):
        return FindingOutcome.REVIEW
    return FindingOutcome.PASS


def _ordered_facts(facts: ContractChangeSet) -> dict[str, object]:
    payload = facts.model_dump(mode="json")
    for key in ("clause_changes", "entity_changes", "region_changes", "feature_changes"):
        payload[key] = sorted(payload[key], key=lambda item: _canonical(item))
    payload["unresolved_clause_ids"] = sorted(payload["unresolved_clause_ids"])
    return payload


def _integrity_findings(
    frozen: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
    facts: ContractChangeSet,
    visual_changes: Sequence[object],
    visual_available: bool,
) -> tuple[FrozenPolicy | None, ContractChangeSet | None, list[Finding]]:
    findings: list[Finding] = []
    checked_frozen: FrozenPolicy | None = None
    checked_facts: ContractChangeSet | None = None
    try:
        checked_frozen = FrozenPolicy.model_validate(frozen)
    except (ValidationError, RecursionError, TypeError, ValueError):
        findings.append(
            _make_finding(
                rule_id="contract-safe.integrity.policy",
                outcome=FindingOutcome.FAIL,
                location="integrity:policy-model",
                remediation="Use a valid frozen policy.",
            )
        )
    if checked_frozen is not None:
        actual_digest = policy_digest(checked_frozen.policy)
        if checked_frozen.canonical_sha256 != actual_digest:
            findings.append(
                _make_finding(
                    rule_id="contract-safe.integrity.policy",
                    outcome=FindingOutcome.FAIL,
                    location="integrity:policy-digest",
                    before_fingerprint=checked_frozen.canonical_sha256,
                    after_fingerprint=actual_digest,
                    remediation="Refreeze the policy from its canonical contents.",
                )
            )
        if (
            checked_frozen.policy.baseline.sha256 != baseline.source.sha256
            or checked_frozen.policy.baseline.format != baseline.source.format
        ):
            findings.append(
                _make_finding(
                    rule_id="contract-safe.integrity.baseline",
                    outcome=FindingOutcome.FAIL,
                    location="integrity:baseline",
                    before_fingerprint=checked_frozen.policy.baseline.sha256,
                    after_fingerprint=_safe_sha(baseline.source.sha256),
                    remediation="Verify the exact frozen baseline artifact.",
                )
            )
    try:
        checked_facts = ContractChangeSet.model_validate(facts)
    except (ValidationError, RecursionError, TypeError, ValueError):
        findings.append(
            _make_finding(
                rule_id="contract-safe.integrity.facts",
                outcome=FindingOutcome.FAIL,
                location="integrity:facts-model",
                remediation="Recompute contract facts from the inspected artifacts.",
            )
        )
    if checked_facts is not None:
        if checked_facts.baseline_sha256 != baseline.source.sha256:
            findings.append(
                _make_finding(
                    rule_id="contract-safe.integrity.facts",
                    outcome=FindingOutcome.FAIL,
                    location="integrity:facts-baseline",
                    before_fingerprint=checked_facts.baseline_sha256,
                    after_fingerprint=_safe_sha(baseline.source.sha256),
                    remediation="Recompute contract facts from this baseline.",
                )
            )
        if checked_facts.candidate_sha256 != candidate.source.sha256:
            findings.append(
                _make_finding(
                    rule_id="contract-safe.integrity.candidate",
                    outcome=FindingOutcome.FAIL,
                    location="integrity:facts-candidate",
                    before_fingerprint=checked_facts.candidate_sha256,
                    after_fingerprint=_safe_sha(candidate.source.sha256),
                    remediation="Recompute contract facts from this candidate.",
                )
            )
        try:
            recomputed = diff_contracts(baseline, candidate)
            if _ordered_facts(checked_facts) != _ordered_facts(recomputed):
                findings.append(
                    _make_finding(
                        rule_id="contract-safe.integrity.facts",
                        outcome=FindingOutcome.FAIL,
                        location="integrity:facts-content",
                        before_fingerprint=_digest(_ordered_facts(checked_facts)),
                        after_fingerprint=_digest(_ordered_facts(recomputed)),
                        remediation="Recompute unmodified contract facts.",
                    )
                )
        except (ValidationError, RecursionError, TypeError, ValueError):
            findings.append(
                _make_finding(
                    rule_id="contract-safe.integrity.contracts",
                    outcome=FindingOutcome.FAIL,
                    location="integrity:contract-models",
                    remediation="Use valid inspected contract models.",
                )
            )
    if not isinstance(visual_available, bool) or not isinstance(visual_changes, list):
        findings.append(
            _make_finding(
                rule_id="contract-safe.integrity.visual-input",
                outcome=FindingOutcome.FAIL,
                location="integrity:visual-input",
                remediation="Provide ordered visual facts and an explicit availability flag.",
            )
        )
    elif len(visual_changes) > MAX_VERDICT_FINDINGS:
        findings.append(
            _make_finding(
                rule_id="contract-safe.integrity.findings-limit",
                outcome=FindingOutcome.FAIL,
                location="integrity:findings-limit",
                before_fingerprint=_digest(len(visual_changes)),
                remediation="Reduce the verification input within the supported finding limit.",
            )
        )
    else:
        try:
            for item in visual_changes:
                VisualPageChange.model_validate(item)
        except (ValidationError, RecursionError, TypeError, ValueError):
            findings.append(
                _make_finding(
                    rule_id="contract-safe.integrity.visual-input",
                    outcome=FindingOutcome.FAIL,
                    location="integrity:visual-input",
                    remediation="Recompute valid visual change facts.",
                )
            )
    return checked_frozen, checked_facts, findings


def _one_clause(document: ContractDocument, clause_id: str) -> ContractClause | None:
    matches = [item for item in document.clauses if item.id == clause_id]
    return matches[0] if len(matches) == 1 else None


def _find_spans(text: str, needle: str) -> tuple[_Span, ...]:
    if not needle:
        return ()
    spans: list[_Span] = []
    start = 0
    while (index := text.find(needle, start)) >= 0:
        spans.append(_Span(index, index + len(needle)))
        start = index + len(needle)
    return tuple(spans)


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _stable_context(value: str) -> str:
    return normalize_text(value)[-32:]


def _occurrences_correspond(
    before_text: str,
    after_text: str,
    before_spans: tuple[_Span, ...],
    after_spans: tuple[_Span, ...],
) -> bool:
    if len(before_spans) != len(after_spans):
        return False
    for before_span, after_span in zip(before_spans, after_spans, strict=True):
        before_prefix = _stable_context(before_text[: before_span.start])
        after_prefix = _stable_context(after_text[: after_span.start])
        before_suffix = normalize_text(before_text[before_span.end :])[:32]
        after_suffix = normalize_text(after_text[after_span.end :])[:32]
        prefix_matches = len(before_prefix) >= 6 and before_prefix == after_prefix
        suffix_matches = len(before_suffix) >= 6 and before_suffix == after_suffix
        if not (prefix_matches or suffix_matches):
            return False
    return True


def _selector_failure(*, rule_id: str, location: str, status: SelectorResolutionStatus) -> Finding:
    return _make_finding(
        rule_id=rule_id,
        outcome=FindingOutcome.FAIL,
        location=location,
        selector_status=status,
        remediation="Restore a unique high-confidence contract selector match.",
    )


def _resolve_rule_clauses(
    baseline: ContractDocument,
    candidate: ContractDocument,
    selector: ClauseSelector,
) -> tuple[
    ContractClause | None,
    ContractClause | None,
    SelectorResolutionStatus,
    SelectorResolutionStatus,
]:
    baseline_resolution = resolve_baseline(baseline, selector)
    candidate_resolution = resolve_candidate(candidate, selector)
    before = None
    after = None
    if (
        baseline_resolution.status is SelectorResolutionStatus.UNIQUE
        and len(baseline_resolution.matches) == 1
    ):
        before = _one_clause(baseline, baseline_resolution.matches[0].clause_id)
    if (
        candidate_resolution.status
        in {
            SelectorResolutionStatus.UNIQUE,
            SelectorResolutionStatus.HIGH_CONFIDENCE,
        }
        and len(candidate_resolution.matches) >= 1
    ):
        after = _one_clause(candidate, candidate_resolution.matches[0].clause_id)
    return (
        before,
        after,
        baseline_resolution.status,
        candidate_resolution.status,
    )


def _expected_phase(
    frozen: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
) -> tuple[list[Finding], list[_ExpectedAssessment], set[tuple[str, str, str]]]:
    findings: list[Finding] = []
    assessments: list[_ExpectedAssessment] = []
    selector_failures: set[tuple[str, str, str]] = set()
    for rule in sorted(frozen.policy.expect, key=lambda item: item.id):
        before_clause, after_clause, before_status, after_status = _resolve_rule_clauses(
            baseline, candidate, rule.selector
        )
        location = f"expected:{rule.id}"
        if before_clause is None:
            findings.append(
                _selector_failure(
                    rule_id="contract-safe.selector.expected-baseline",
                    location=location,
                    status=before_status,
                )
            )
            selector_failures.add((rule.id, "baseline", before_status.value))
            continue
        if after_clause is None:
            findings.append(
                _selector_failure(
                    rule_id="contract-safe.selector.expected-candidate",
                    location=location,
                    status=after_status,
                )
            )
            selector_failures.add((rule.id, "candidate", after_status.value))
            continue
        operation = rule.operation
        before_text = _nfc(before_clause.text)
        after_text = _nfc(after_clause.text)
        before_value = _nfc(operation.before)
        after_value = _nfc(operation.after)
        before_spans = _find_spans(before_text, before_value)
        after_spans = _find_spans(after_text, after_value)
        counted = (
            len(before_spans) == operation.occurrences
            and len(after_spans) == operation.occurrences
            and before_text.count(before_value) == operation.occurrences
            and after_text.count(after_value) == operation.occurrences
            and after_text.count(before_value) == 0
        )
        corresponds = counted and _occurrences_correspond(
            before_text, after_text, before_spans, after_spans
        )
        applied = counted
        reconstructed = before_text.replace(before_value, after_value, operation.occurrences)
        exact = applied and normalize_text(reconstructed) == normalize_text(after_text)
        rule_location = f"{location}:{_clause_location(before_clause, after_clause)}"
        if not applied:
            findings.append(
                _make_finding(
                    rule_id=f"contract-safe.expected.{rule.id}",
                    outcome=FindingOutcome.FAIL,
                    location=rule_location,
                    before_fingerprint=before_clause.fingerprint,
                    after_fingerprint=after_clause.fingerprint,
                    remediation="Apply the declared exact replacement exactly once per occurrence.",
                    locations=[*before_clause.evidence, *after_clause.evidence],
                )
            )
        else:
            findings.append(
                _make_finding(
                    rule_id=f"contract-safe.expected.{rule.id}",
                    outcome=FindingOutcome.PASS,
                    location=rule_location,
                    before_fingerprint=before_clause.fingerprint,
                    after_fingerprint=after_clause.fingerprint,
                    remediation="No action required.",
                    locations=[*before_clause.evidence, *after_clause.evidence],
                )
            )
        assessments.append(
            _ExpectedAssessment(
                rule_id=rule.id,
                before_clause=before_clause,
                after_clause=after_clause,
                before_spans=before_spans if applied else (),
                after_spans=after_spans if applied else (),
                after_value=after_value,
                corresponds=corresponds,
                applied=applied,
                exact=exact,
            )
        )
    assessments = _collective_exactness(assessments)
    by_rule_id = {item.rule_id: item for item in assessments}
    adjusted: list[Finding] = []
    for finding in findings:
        prefix = "contract-safe.expected."
        assessment = by_rule_id.get(finding.rule_id.removeprefix(prefix))
        if (
            finding.rule_id.startswith(prefix)
            and finding.outcome is FindingOutcome.PASS
            and assessment is not None
            and not assessment.applied
        ):
            adjusted.append(
                _make_finding(
                    rule_id=finding.rule_id,
                    outcome=FindingOutcome.FAIL,
                    location=finding.location,
                    before_fingerprint=finding.evidence.before_fingerprint,
                    after_fingerprint=finding.evidence.after_fingerprint,
                    remediation="Apply the declared exact replacement exactly once per occurrence.",
                    locations=finding.evidence.locations,
                )
            )
        else:
            adjusted.append(finding)
    return adjusted, assessments, selector_failures


def _collective_exactness(
    assessments: list[_ExpectedAssessment],
) -> list[_ExpectedAssessment]:
    grouped: dict[tuple[str, str], list[_ExpectedAssessment]] = {}
    for assessment in assessments:
        grouped.setdefault((assessment.before_clause.id, assessment.after_clause.id), []).append(
            assessment
        )
    exact_pairs: dict[tuple[str, str], bool] = {}
    for pair, items in grouped.items():
        if not all(item.applied for item in items):
            exact_pairs[pair] = False
            continue
        replacements = sorted(
            ((span, item.after_value) for item in items for span in item.before_spans),
            key=lambda item: (item[0].start, item[0].end, item[1]),
        )
        after_spans = sorted(
            (span for item in items for span in item.after_spans),
            key=lambda item: (item.start, item.end),
        )
        before_overlaps = any(
            left.end > right.start for left, right in pairwise(item[0] for item in replacements)
        )
        after_overlaps = any(left.end > right.start for left, right in pairwise(after_spans))
        if before_overlaps or after_overlaps:
            exact_pairs[pair] = False
            continue
        baseline_text = _nfc(items[0].before_clause.text)
        pieces: list[str] = []
        cursor = 0
        for span, after_value in replacements:
            pieces.extend((baseline_text[cursor : span.start], after_value))
            cursor = span.end
        pieces.append(baseline_text[cursor:])
        exact_pairs[pair] = normalize_text("".join(pieces)) == normalize_text(
            items[0].after_clause.text
        )
    return [
        replace(
            item,
            applied=item.applied
            and (exact_pairs[(item.before_clause.id, item.after_clause.id)] or item.corresponds),
            exact=exact_pairs[(item.before_clause.id, item.after_clause.id)],
        )
        for item in assessments
    ]


def _allow_phase(
    frozen: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
) -> tuple[list[Finding], dict[tuple[str, str], set[str]]]:
    findings: list[Finding] = []
    allowed: dict[tuple[str, str], set[str]] = {}
    ordered_rules = sorted(
        frozen.policy.allow,
        key=lambda item: _canonical(item.model_dump(mode="json")),
    )
    for index, rule in enumerate(ordered_rules):
        before, after, before_status, after_status = _resolve_rule_clauses(
            baseline, candidate, rule.selector
        )
        location = f"allow:{index}:{_digest(rule.model_dump(mode='json'))[:24]}"
        if before is None:
            findings.append(
                _selector_failure(
                    rule_id="contract-safe.selector.allow-baseline",
                    location=location,
                    status=before_status,
                )
            )
            continue
        if after is None:
            findings.append(
                _selector_failure(
                    rule_id="contract-safe.selector.allow-candidate",
                    location=location,
                    status=after_status,
                )
            )
            continue
        allowed.setdefault((before.id, after.id), set()).update(rule.kinds)
    return findings, allowed


def _authorized_spans(
    assessments: list[_ExpectedAssessment], *, before: bool
) -> dict[str, tuple[_Span, ...]]:
    result: dict[str, list[_Span]] = {}
    for assessment in assessments:
        if not assessment.applied:
            continue
        clause = assessment.before_clause if before else assessment.after_clause
        spans = assessment.before_spans if before else assessment.after_spans
        result.setdefault(clause.id, []).extend(spans)
    return {
        clause_id: tuple(sorted(spans, key=lambda item: (item.start, item.end)))
        for clause_id, spans in result.items()
    }


def _inside_any(span: _Span, authorized: tuple[_Span, ...]) -> bool:
    return any(item.start <= span.start and item.end >= span.end for item in authorized)


def _entity_side_authorized(
    clause: ContractClause | None,
    kind: EntityKind,
    value: str | None,
    authorized: dict[str, tuple[_Span, ...]],
) -> bool:
    if clause is None or value is None:
        return False
    matching = [
        entity
        for entity in clause.entities
        if entity.kind is kind and entity.normalized_value == value
    ]
    if len(matching) != 1:
        return False
    text_spans = _find_spans(_nfc(clause.text), _nfc(matching[0].text))
    return len(text_spans) == 1 and _inside_any(text_spans[0], authorized.get(clause.id, ()))


def _entity_evidence(
    clause: ContractClause | None, kind: EntityKind, value: str | None
) -> list[EvidenceRef]:
    if clause is None or value is None:
        return []
    return [
        evidence
        for entity in clause.entities
        if entity.kind is kind and entity.normalized_value == value
        for evidence in entity.evidence
    ]


def _protected_entity_findings(
    frozen: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
    facts: ContractChangeSet,
    assessments: list[_ExpectedAssessment],
) -> list[Finding]:
    before_spans = _authorized_spans(assessments, before=True)
    after_spans = _authorized_spans(assessments, before=False)
    clause_changes = {item.id: item for item in facts.clause_changes}
    findings: list[Finding] = []
    for change in sorted(facts.entity_changes, key=lambda item: item.id):
        target = _ENTITY_TARGET[change.kind]
        if target not in frozen.policy.protect:
            continue
        clause_change = clause_changes.get(change.clause_change_id)
        if clause_change is None:
            authorized = False
            before_clause = None
            after_clause = None
        else:
            before_clause = (
                _one_clause(baseline, clause_change.before_clause_id)
                if clause_change.before_clause_id is not None
                else None
            )
            after_clause = (
                _one_clause(candidate, clause_change.after_clause_id)
                if clause_change.after_clause_id is not None
                else None
            )
            authorized = _entity_side_authorized(
                before_clause, change.kind, change.before_value, before_spans
            ) and _entity_side_authorized(
                after_clause, change.kind, change.after_value, after_spans
            )
        if authorized:
            continue
        findings.append(
            _make_finding(
                rule_id=f"contract-safe.protected.{target.value}",
                outcome=FindingOutcome.FAIL,
                location=f"entity:{change.id}",
                before_fingerprint=(
                    _digest([change.kind.value, change.before_value])
                    if change.before_value is not None
                    else None
                ),
                after_fingerprint=(
                    _digest([change.kind.value, change.after_value])
                    if change.after_value is not None
                    else None
                ),
                remediation="Restore the protected entity or declare one exact replacement span.",
                locations=[
                    *_entity_evidence(before_clause, change.kind, change.before_value),
                    *_entity_evidence(after_clause, change.kind, change.after_value),
                ],
            )
        )
    return findings


def _protected_region_findings(frozen: FrozenPolicy, facts: ContractChangeSet) -> list[Finding]:
    findings: list[Finding] = []
    for change in sorted(facts.region_changes, key=lambda item: item.id):
        target = _REGION_TARGET[change.kind.value]
        if target not in frozen.policy.protect:
            continue
        findings.append(
            _make_finding(
                rule_id=f"contract-safe.protected.{target.value}",
                outcome=FindingOutcome.FAIL,
                location=f"region:{change.id}",
                before_fingerprint=change.before_fingerprint,
                after_fingerprint=change.after_fingerprint,
                remediation="Restore the protected contract region.",
            )
        )
    return findings


def _matching_features(
    document: ContractDocument, kind: object, fingerprint_value: str | None
) -> list[DocumentFeature]:
    if fingerprint_value is None:
        return []
    return [
        feature
        for feature in document.features
        if feature.kind is kind and feature.fingerprint == fingerprint_value
    ]


def _evidence_box(evidence: EvidenceRef) -> tuple[int, Rect] | None:
    if evidence.rendered_page_index is not None and evidence.rendered_bbox is not None:
        return (evidence.rendered_page_index, evidence.rendered_bbox)
    if evidence.page_index is not None and evidence.bbox is not None:
        return (evidence.page_index, evidence.bbox)
    return None


def _evidence_intersects(left: EvidenceRef, right: EvidenceRef) -> bool:
    if left.block_id == right.block_id:
        return True
    left_geometry = _evidence_box(left)
    right_geometry = _evidence_box(right)
    return (
        left_geometry is not None
        and right_geometry is not None
        and left_geometry[0] == right_geometry[0]
        and rects_overlap(left_geometry[1], right_geometry[1])
    )


def _protected_evidence(
    frozen: FrozenPolicy, baseline: ContractDocument, candidate: ContractDocument
) -> list[EvidenceRef]:
    evidence: list[EvidenceRef] = []
    for region in [*baseline.protected_regions, *candidate.protected_regions]:
        if _REGION_TARGET[region.kind.value] in frozen.policy.protect:
            evidence.extend(region.evidence)
    return evidence


def _feature_findings(
    frozen: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
    facts: ContractChangeSet,
) -> list[Finding]:
    findings: list[Finding] = []
    protected = _protected_evidence(frozen, baseline, candidate)
    for change in sorted(facts.feature_changes, key=lambda item: item.id):
        features = [
            *_matching_features(baseline, change.kind, change.before_fingerprint),
            *_matching_features(candidate, change.kind, change.after_fingerprint),
        ]
        overlaps = any(
            _evidence_intersects(feature_evidence, protected_evidence)
            for feature in features
            for feature_evidence in feature.evidence
            for protected_evidence in protected
        )
        if change.kind.value == "metadata":
            if overlaps or change.business_relevance == "business":
                outcome = FindingOutcome.FAIL
                approvable = False
                remediation = "Restore or explicitly correct the business metadata."
            elif frozen.policy.metadata.non_business_change == "review":
                outcome = FindingOutcome.REVIEW
                approvable = True
                remediation = "Review the validated non-business metadata change."
            else:
                outcome = FindingOutcome.PASS
                approvable = False
                remediation = "No action required."
            rule_id = "contract-safe.metadata"
        else:
            outcome = FindingOutcome.FAIL if overlaps else FindingOutcome.REVIEW
            approvable = not overlaps
            remediation = (
                "Restore the feature change intersecting protected content."
                if overlaps
                else "Review the document feature change."
            )
            rule_id = f"contract-safe.feature.{change.kind.value}"
        findings.append(
            _make_finding(
                rule_id=rule_id,
                outcome=outcome,
                location=f"feature:{change.id}",
                before_fingerprint=change.before_fingerprint,
                after_fingerprint=change.after_fingerprint,
                remediation=remediation,
                approvable=approvable,
                locations=[evidence for feature in features for evidence in feature.evidence],
            )
        )
    return findings


def _rendered_boxes(items: list[EvidenceRef], page: int) -> list[Rect]:
    return [
        item.rendered_bbox
        for item in items
        if item.rendered_page_index == page and item.rendered_bbox is not None
    ]


def _expected_envelopes(assessments: list[_ExpectedAssessment], pages: set[int]) -> dict[int, Rect]:
    by_page: dict[int, list[Rect]] = {page: [] for page in pages}
    for assessment in assessments:
        if not assessment.applied:
            continue
        for page in pages:
            by_page[page].extend(_rendered_boxes(assessment.before_clause.evidence, page))
            by_page[page].extend(_rendered_boxes(assessment.after_clause.evidence, page))
    return {
        page: envelope
        for page, boxes in by_page.items()
        if (envelope := union_rectangles(boxes)) is not None
    }


def _protected_boxes_by_page(
    frozen: FrozenPolicy, baseline: ContractDocument, candidate: ContractDocument
) -> dict[int, list[Rect]]:
    result: dict[int, list[Rect]] = {}
    for item in _protected_evidence(frozen, baseline, candidate):
        geometry = _evidence_box(item)
        if geometry is not None:
            result.setdefault(geometry[0], []).append(geometry[1])
    return result


def _visual_findings(
    frozen: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
    assessments: list[_ExpectedAssessment],
    visual_changes: list[VisualPageChange],
) -> list[Finding]:
    findings: list[Finding] = []
    pages = {
        page
        for change in visual_changes
        for page in (change.before_page, change.after_page)
        if page is not None
    }
    envelopes = _expected_envelopes(assessments, pages)
    protected = _protected_boxes_by_page(frozen, baseline, candidate)
    ordered_changes = sorted(
        visual_changes,
        key=lambda item: _canonical(item.model_dump(mode="json")),
    )
    for change in ordered_changes:
        location = f"visual:{change.before_page}:{change.after_page}:{change.id}"
        change_location = _visual_location(change)
        if change.before_page is not None and change.after_page is None:
            findings.append(
                assess_page_deletion(
                    location=location,
                    locations=[change_location],
                )
            )
            continue
        if (
            change.before_page is None
            or change.after_page is None
            or change.before_page != change.after_page
        ):
            findings.append(
                assess_pagination_reflow(
                    policy=frozen.policy.visual,
                    location=location,
                    locations=[change_location],
                )
            )
            continue
        page = change.before_page
        ordered_regions = sorted(
            change.regions,
            key=lambda item: (item.x0, item.y0, item.x1, item.y1),
        )
        if not ordered_regions and change.changed_pixel_ratio > 0:
            findings.append(
                _make_finding(
                    rule_id="contract-safe.visual.outside-envelope",
                    outcome=FindingOutcome.REVIEW,
                    location=location,
                    remediation="Review the unlocalized rendered change.",
                    approvable=True,
                    locations=[change_location],
                )
            )
            continue
        for index, region in enumerate(ordered_regions):
            findings.append(
                assess_visual_change(
                    expected_box=envelopes.get(page),
                    changed=region,
                    padding=frozen.policy.visual.layout_envelope_padding_points,
                    protected_boxes=protected.get(page, []),
                    location=f"{location}:region:{index}",
                    locations=[_visual_location(change, region=region, index=index)],
                )
            )
    return findings


def _visual_location(
    change: VisualPageChange, *, region: Rect | None = None, index: int | None = None
) -> EvidenceRef:
    page = change.after_page if change.after_page is not None else change.before_page
    suffix = f":region:{index}" if index is not None else ""
    return EvidenceRef(
        block_id=f"visual:{change.id}{suffix}",
        rendered_page_index=page,
        rendered_bbox=region,
    )


def _clause_pair(change: ClauseChange) -> tuple[str, str] | None:
    if change.before_clause_id is None or change.after_clause_id is None:
        return None
    return (change.before_clause_id, change.after_clause_id)


def _clause_findings(
    facts: ContractChangeSet,
    assessments: list[_ExpectedAssessment],
    allowed: dict[tuple[str, str], set[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    assessment_by_pair: dict[tuple[str, str], list[_ExpectedAssessment]] = {}
    for item in assessments:
        assessment_by_pair.setdefault((item.before_clause.id, item.after_clause.id), []).append(
            item
        )
    for unresolved in sorted(facts.unresolved_clause_ids):
        findings.append(
            _make_finding(
                rule_id="contract-safe.unresolved-clause",
                outcome=FindingOutcome.FAIL,
                location=f"unresolved:{_digest(unresolved)[:24]}",
                remediation="Resolve the ambiguous clause pairing.",
            )
        )
    for change in sorted(facts.clause_changes, key=lambda item: item.id):
        pair = _clause_pair(change)
        expected = assessment_by_pair.get(pair, []) if pair is not None else []
        if expected and all(item.exact for item in expected):
            continue
        kinds = allowed.get(pair, set()) if pair is not None else set()
        location = _clause_location_from_change(change)
        if change.kind.value in kinds:
            findings.append(
                _make_finding(
                    rule_id="contract-safe.allow",
                    outcome=FindingOutcome.REVIEW,
                    location=location,
                    before_fingerprint=(
                        _digest(change.before_text) if change.before_text is not None else None
                    ),
                    after_fingerprint=(
                        _digest(change.after_text) if change.after_text is not None else None
                    ),
                    remediation="Review the explicit allowed clause change.",
                    approvable=True,
                    locations=[*change.before_evidence, *change.after_evidence],
                )
            )
            continue
        findings.append(
            _make_finding(
                rule_id="contract-safe.unexplained-clause",
                outcome=FindingOutcome.FAIL,
                location=location,
                before_fingerprint=(
                    _digest(change.before_text) if change.before_text is not None else None
                ),
                after_fingerprint=(
                    _digest(change.after_text) if change.after_text is not None else None
                ),
                remediation="Restore the clause or declare an exact expected operation.",
                locations=[*change.before_evidence, *change.after_evidence],
            )
        )
    return findings


def _clause_location_from_change(change: ClauseChange) -> str:
    return f"clause-change:{change.id}"


def _phase_rank(finding: Finding) -> tuple[int, str, str, str]:
    rule_id = finding.rule_id
    if rule_id.startswith("contract-safe.integrity"):
        phase = 0
    elif ".selector." in rule_id:
        phase = 1
    elif rule_id.startswith("contract-safe.expected."):
        phase = 2
    elif rule_id.startswith("contract-safe.protected."):
        phase = 3
    elif rule_id.startswith(("contract-safe.feature.", "contract-safe.metadata")):
        phase = 4
    elif rule_id.startswith(
        ("contract-safe.allow", "contract-safe.unexplained", "contract-safe.unresolved")
    ):
        phase = 5
    else:
        phase = 6
    return (phase, rule_id, finding.location, finding.id)


def _bounded_findings(findings: list[Finding]) -> list[Finding]:
    if len(findings) <= MAX_VERDICT_FINDINGS:
        return findings
    overflow = _make_finding(
        rule_id="contract-safe.integrity.findings-limit",
        outcome=FindingOutcome.FAIL,
        location="integrity:findings-limit",
        before_fingerprint=_digest([item.id for item in findings]),
        remediation="Reduce the verification input within the supported finding limit.",
    )
    return sorted([overflow, *findings[: MAX_VERDICT_FINDINGS - 1]], key=_phase_rank)


def evaluate_contract(
    policy: FrozenPolicy,
    baseline: ContractDocument,
    candidate: ContractDocument,
    facts: ContractChangeSet,
    visual_changes: list[VisualPageChange],
    visual_available: bool,
) -> RawVerdict:
    """Evaluate observed facts using only the frozen contract-safe policy."""
    checked_policy, checked_facts, integrity = _integrity_findings(
        policy, baseline, candidate, facts, visual_changes, visual_available
    )
    policy_sha = _safe_sha(getattr(policy, "canonical_sha256", ""))
    baseline_sha = _safe_sha(getattr(getattr(baseline, "source", None), "sha256", ""))
    candidate_sha = _safe_sha(getattr(getattr(candidate, "source", None), "sha256", ""))
    if integrity or checked_policy is None or checked_facts is None:
        findings = sorted(integrity, key=_phase_rank)
        return RawVerdict(
            outcome=FindingOutcome.FAIL,
            policy_sha256=policy_sha,
            baseline_sha256=baseline_sha,
            candidate_sha256=candidate_sha,
            findings=findings,
        )

    expected_findings, assessments, _ = _expected_phase(checked_policy, baseline, candidate)
    allow_findings, allowed = _allow_phase(checked_policy, baseline, candidate)
    findings = [*expected_findings, *allow_findings]
    findings.extend(
        _protected_entity_findings(checked_policy, baseline, candidate, checked_facts, assessments)
    )
    findings.extend(_protected_region_findings(checked_policy, checked_facts))
    findings.extend(_feature_findings(checked_policy, baseline, candidate, checked_facts))
    findings.extend(_clause_findings(checked_facts, assessments, allowed))
    availability = assess_visual_availability(
        policy=checked_policy.policy.visual, available=visual_available
    )
    if availability is not None:
        findings.append(availability)
    elif visual_changes:
        findings.extend(
            _visual_findings(
                checked_policy,
                baseline,
                candidate,
                assessments,
                [VisualPageChange.model_validate(item) for item in visual_changes],
            )
        )
    findings.sort(key=_phase_rank)
    findings = _bounded_findings(findings)
    return RawVerdict(
        outcome=_combine(findings),
        policy_sha256=checked_policy.canonical_sha256,
        baseline_sha256=baseline.source.sha256,
        candidate_sha256=candidate.source.sha256,
        findings=findings,
    )
