from __future__ import annotations

import json
from typing import Literal

import pytest
from pydantic import ValidationError

from artifactdiff.contract import (
    ClauseLabel,
    ClauseSelector,
    ContractClause,
    ContractDocument,
    EvidenceRef,
    LanguageKind,
    LanguageProfile,
    ProtectedRegion,
    ProtectedRegionKind,
)
from artifactdiff.contract.entities import extract_entities
from artifactdiff.contract.models import DocumentFeature, DocumentFeatureKind
from artifactdiff.models import Rect, SourceDescriptor, VisualPageChange
from artifactdiff.normalize import fingerprint, normalize_text
from artifactdiff.policy import (
    AllowRule,
    ContractPolicy,
    ExactReplace,
    ExpectedRule,
    FrozenPolicy,
    MetadataPolicy,
    PolicyBaseline,
    PolicyPluginRequirement,
    ProtectedTarget,
    VisualPolicy,
    freeze_policy,
    policy_digest,
)
from artifactdiff.verification import (
    ContractChangeSet,
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
    diff_contracts,
    evaluate_contract,
    finding_id,
)


def _clause(
    clause_id: str,
    text: str,
    *,
    label: str = "article ii",
    heading: str = "Payment Terms",
    evidence: list[EvidenceRef] | None = None,
) -> ContractClause:
    clause_evidence = evidence or [EvidenceRef(block_id=f"block-{clause_id}")]
    entities = extract_entities(text, clause_id, clause_evidence[0])
    return ContractClause(
        id=clause_id,
        label=ClauseLabel(printed=label, normalized=label, scheme="article"),
        heading=heading,
        text=text,
        normalized_text=normalize_text(text),
        fingerprint=fingerprint(text),
        evidence=clause_evidence,
        entities=entities,
    )


def _contract(
    *clauses: ContractClause,
    sha: str,
    language: LanguageKind = LanguageKind.ENGLISH,
    features: list[DocumentFeature] | None = None,
    regions: list[ProtectedRegion] | None = None,
) -> ContractDocument:
    return ContractDocument(
        source=SourceDescriptor(path="contract.docx", sha256=sha * 64, format="docx", size_bytes=1),
        language=LanguageProfile(kind=language),
        clauses=list(clauses),
        entities=[entity for clause in clauses for entity in clause.entities],
        features=features or [],
        protected_regions=regions or [],
    )


def _frozen(
    baseline: ContractDocument,
    *,
    before: str,
    after: str,
    occurrences: int = 1,
    anchor: str = "Payment obligations",
    allow: bool = False,
    protect: frozenset[ProtectedTarget] | None = None,
    metadata: MetadataPolicy | None = None,
    visual: VisualPolicy | None = None,
) -> FrozenPolicy:
    payment = baseline.clauses[0]
    selector = ClauseSelector(
        clause_label=payment.label.normalized,
        heading=payment.heading,
        ancestor_path=payment.ancestor_path,
        anchor=anchor,
        baseline_fingerprint=payment.fingerprint,
        occurrences=occurrences,
    )
    expected = ExpectedRule(
        id="payment-window",
        selector=selector,
        operation=ExactReplace(before=before, after=after, occurrences=occurrences),
    )
    policy = ContractPolicy(
        baseline=PolicyBaseline(sha256=baseline.source.sha256, format="docx"),
        expect=[expected],
        allow=[AllowRule(selector=selector, kinds=frozenset({"modified"}))] if allow else [],
        protect=protect if protect is not None else frozenset(ProtectedTarget),
        metadata=metadata or MetadataPolicy(),
        visual=visual or VisualPolicy(),
    )
    return freeze_policy(baseline, policy)


def _evaluate(
    baseline: ContractDocument,
    candidate: ContractDocument,
    frozen: FrozenPolicy,
    *,
    visual_changes: list[VisualPageChange] | None = None,
    visual_available: bool = True,
    facts: ContractChangeSet | None = None,
) -> RawVerdict:
    observed = facts or diff_contracts(baseline, candidate)
    return evaluate_contract(
        frozen,
        baseline,
        candidate,
        observed,
        visual_changes or [],
        visual_available,
    )


_SEMANTIC_POLICY_BYPASSES = (
    "empty-expect",
    "allow-network",
    "allow-model",
    "missing-fingerprint",
    "no-op",
    "occurrence-mismatch",
)


def _redigested_semantically_invalid_frozen(frozen: FrozenPolicy, case: str) -> FrozenPolicy:
    policy = frozen.policy.model_copy(deep=True)
    if case == "empty-expect":
        policy.expect = []
    elif case in {"allow-network", "allow-model"}:
        policy.required_plugins = {
            "unsafe-plugin": PolicyPluginRequirement(
                version="1",
                distribution="unsafe-plugin",
                allow_network=case == "allow-network",
                allow_model=case == "allow-model",
            )
        }
    elif case == "missing-fingerprint":
        policy.expect[0].selector.baseline_fingerprint = ""
    elif case == "no-op":
        policy.expect[0].operation.after = policy.expect[0].operation.before
    else:
        policy.expect[0].operation.occurrences = 2
    checked = ContractPolicy.model_validate(policy)
    return FrozenPolicy(policy=checked, canonical_sha256=policy_digest(checked))


def test_finding_id_hashes_only_the_stable_rule_identity() -> None:
    assert (
        finding_id(
            rule_id="contract-safe.expected.payment-window",
            rule_version="1.0",
            location="clause:payment",
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
        )
        == "finding-ec43c2025fa3185a992046cf"
    )


def test_verdict_models_reject_extras_coercions_and_unordered_locations() -> None:
    with pytest.raises(ValidationError):
        FindingEvidence.model_validate({"locations": {"block-a", "block-b"}})
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                "id": "finding-" + "a" * 24,
                "rule_id": "contract-safe.test",
                "outcome": "pass",
                "location": 4,
                "evidence": {},
                "remediation": "none",
            }
        )
    with pytest.raises(ValidationError):
        RawVerdict.model_validate(
            {
                "outcome": "pass",
                "policy_sha256": "a" * 64,
                "baseline_sha256": "b" * 64,
                "candidate_sha256": "c" * 64,
                "findings": [],
                "unknown": True,
            }
        )


def test_verdict_models_bound_privacy_sensitive_text_and_collections() -> None:
    with pytest.raises(ValidationError):
        FindingEvidence(before_excerpt="x" * 513)
    with pytest.raises(ValidationError):
        FindingEvidence(locations=[EvidenceRef(block_id=f"block-{index}") for index in range(33)])
    with pytest.raises(ValidationError):
        Finding(
            id="finding-" + "a" * 24,
            rule_id="contract-safe.test",
            outcome=FindingOutcome.FAIL,
            location="x" * 513,
            evidence=FindingEvidence(),
            remediation="review",
        )


def test_raw_verdict_serialization_is_utf8_json_without_implicit_content() -> None:
    finding = Finding(
        id="finding-" + "a" * 24,
        rule_id="contract-safe.test",
        outcome=FindingOutcome.PASS,
        location="clause:payment",
        evidence=FindingEvidence(before_fingerprint="b" * 64),
        remediation="No action required.",
    )
    verdict = RawVerdict(
        outcome=FindingOutcome.PASS,
        policy_sha256="a" * 64,
        baseline_sha256="b" * 64,
        candidate_sha256="c" * 64,
        findings=[finding],
    )

    payload = json.loads(verdict.canonical_bytes())

    assert payload["outcome"] == "pass"
    assert payload["findings"][0]["location"] == "clause:payment"
    assert verdict.canonical_bytes() == verdict.canonical_bytes()


def test_raw_verdict_rejects_duplicate_finding_ids() -> None:
    finding = Finding(
        id="finding-" + "a" * 24,
        rule_id="contract-safe.test",
        outcome=FindingOutcome.FAIL,
        location="integrity:test",
        evidence=FindingEvidence(),
        remediation="Repair the test input.",
    )

    with pytest.raises(ValidationError):
        RawVerdict(
            outcome=FindingOutcome.FAIL,
            policy_sha256="a" * 64,
            baseline_sha256="b" * 64,
            candidate_sha256="c" * 64,
            findings=[finding, finding],
        )


@pytest.mark.parametrize(
    ("language", "label", "heading", "before_text", "after_text", "before", "after"),
    [
        (
            LanguageKind.ENGLISH,
            "article ii",
            "Payment Terms",
            "Article II Payment Terms\nPayment obligations: pay within 30 days.",
            "Article II Payment Terms\nPayment obligations: pay within 45 days.",
            "30 days",
            "45 days",
        ),
        (
            LanguageKind.CHINESE,
            "第四条",
            "付款条款",
            "第四条 付款条款\nPayment obligations 付款义务：应在 30 天内付款。",
            "第四条 付款条款\nPayment obligations 付款义务：应在 45 天内付款。",
            "30 天",
            "45 天",
        ),
        (
            LanguageKind.BILINGUAL,
            "第四条 section 4",
            "Payment Terms 付款条款",
            "Payment Terms 付款条款\nPayment obligations 付款义务：within 30 days（30 天内）。",
            "Payment Terms 付款条款\nPayment obligations 付款义务：within 45 days（45 天内）。",
            "30 days（30 天",
            "45 days（45 天",
        ),
    ],
)
def test_exact_declared_edit_passes_multilingual_flagship(
    language: LanguageKind,
    label: str,
    heading: str,
    before_text: str,
    after_text: str,
    before: str,
    after: str,
) -> None:
    baseline = _contract(
        _clause("before-payment", before_text, label=label, heading=heading),
        sha="a",
        language=language,
    )
    candidate = _contract(
        _clause("after-payment", after_text, label=label, heading=heading),
        sha="b",
        language=language,
    )

    verdict = _evaluate(baseline, candidate, _frozen(baseline, before=before, after=after))

    assert verdict.outcome is FindingOutcome.PASS
    assert verdict.findings
    assert all(finding.outcome is FindingOutcome.PASS for finding in verdict.findings)


def test_expected_operation_finding_links_semantic_evidence() -> None:
    before_evidence = [EvidenceRef(block_id="before-payment")]
    after_evidence = [EvidenceRef(block_id="after-payment")]
    baseline, candidate = _exact_pair(
        before_evidence=before_evidence,
        after_evidence=after_evidence,
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    expected = next(item for item in verdict.findings if ".expected." in item.rule_id)
    assert expected.evidence.locations == [*after_evidence, *before_evidence]


@pytest.mark.parametrize(
    ("candidate_body", "expected_after"),
    [
        ("Payment obligations: pay within 30 days.", "45 days"),
        ("Payment obligations: pay within 46 days.", "45 days"),
        ("Payment obligations: pay within 45 days and again within 45 days.", "45 days"),
    ],
)
def test_missing_wrong_or_duplicated_expected_operation_fails_nonapprovably(
    candidate_body: str, expected_after: str
) -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Article II Payment Terms\nPayment obligations: pay within 30 days.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause("after-payment", f"Article II Payment Terms\n{candidate_body}"), sha="b"
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after=expected_after),
    )

    expected_findings = [
        finding
        for finding in verdict.findings
        if finding.rule_id.startswith("contract-safe.expected")
    ]
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected_findings
    assert all(not finding.approvable for finding in expected_findings)


def test_extra_edit_inside_explicit_allow_reviews_approvably() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Article II Payment Terms\nPayment obligations: pay within 30 days.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Article II Payment Terms\nPayment obligations: pay within 45 days. No late fee.",
        ),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days", allow=True),
    )

    allow_findings = [item for item in verdict.findings if item.rule_id == "contract-safe.allow"]
    assert verdict.outcome is FindingOutcome.REVIEW
    assert len(allow_findings) == 1
    assert allow_findings[0].approvable is True


def test_exact_operation_at_wrong_repeated_context_fails_nonapprovably() -> None:
    context = "Repeated payment context with stable words "
    suffix = " and identical trailing words for review."
    baseline_text = f"Payment obligations\n{context}RED{suffix}\n{context}YELLOW{suffix}"
    candidate_text = f"Payment obligations\n{context}GREEN{suffix}\n{context}BLUE{suffix}"
    baseline = _contract(_clause("before-payment", baseline_text), sha="a")
    candidate = _contract(_clause("after-payment", candidate_text), sha="b")

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="RED",
            after="BLUE",
            allow=True,
        ),
    )

    expected = next(
        item for item in verdict.findings if item.rule_id == "contract-safe.expected.payment-window"
    )
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected.outcome is FindingOutcome.FAIL
    assert expected.approvable is False


def test_near_collision_cannot_credit_expected_operation_at_wrong_occurrence() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nFirst required position: RED\nSecond unrelated position: RDX",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nFirst required position: GREEN\nSecond unrelated position: BLUE",
        ),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="RED", after="BLUE", allow=True),
    )

    expected = next(
        item for item in verdict.findings if item.rule_id == "contract-safe.expected.payment-window"
    )
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected.outcome is FindingOutcome.FAIL
    assert expected.approvable is False


def test_multiple_occurrences_of_one_operation_pass_in_stable_order() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nPrimary RED; Payment obligations backup RED.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nPrimary BLUE; Payment obligations backup BLUE.",
        ),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="RED",
            after="BLUE",
            occurrences=2,
            anchor="Payment obligations",
        ),
    )

    assert verdict.outcome is FindingOutcome.PASS
    assert all(item.outcome is FindingOutcome.PASS for item in verdict.findings)


def test_ambiguous_equal_cost_occurrence_mapping_fails_nonapprovably() -> None:
    baseline = _contract(
        _clause("before-payment", "Payment obligations\nRED X X"),
        sha="a",
    )
    candidate = _contract(
        _clause("after-payment", "Payment obligations\nX X BLUE"),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="RED", after="BLUE", allow=True),
    )

    expected = next(
        item for item in verdict.findings if item.rule_id == "contract-safe.expected.payment-window"
    )
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected.outcome is FindingOutcome.FAIL
    assert expected.approvable is False


def test_occurrence_alignment_budget_is_total_and_fails_closed() -> None:
    baseline_text = f"Payment obligations\n{'A' * 1050} RED {'B' * 1050} YELLOW"
    candidate_text = baseline_text.replace("RED", "BLUE").replace("YELLOW", "GREEN")
    baseline = _contract(_clause("before-payment", baseline_text), sha="a")
    candidate = _contract(_clause("after-payment", candidate_text), sha="b")

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="RED",
            after="BLUE",
            allow=True,
        ),
    )

    expected = next(
        item for item in verdict.findings if item.rule_id == "contract-safe.expected.payment-window"
    )
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected.outcome is FindingOutcome.FAIL
    assert expected.approvable is False


def test_extra_edit_without_explicit_allow_fails() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Article II Payment Terms\nPayment obligations: pay within 30 days.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Article II Payment Terms\nPayment obligations: pay within 45 days. No late fee.",
        ),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert any(item.rule_id == "contract-safe.unexplained-clause" for item in verdict.findings)


def test_all_entity_kinds_wholly_inside_exact_authorized_spans_pass() -> None:
    before = "Alpha Ltd. shall pay USD 100 on 2026-08-04 within 30 days with a 5% fee."
    after = "Beta Ltd. shall pay EUR 200 on 2026-09-05 within 45 days with a 7% fee."
    baseline = _contract(_clause("before-payment", f"Payment obligations\n{before}"), sha="a")
    candidate = _contract(_clause("after-payment", f"Payment obligations\n{after}"), sha="b")

    verdict = _evaluate(baseline, candidate, _frozen(baseline, before=before, after=after))

    assert verdict.outcome is FindingOutcome.PASS
    assert not any("protected" in item.rule_id for item in verdict.findings)


def test_party_change_outside_exact_authorized_span_fails() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nParty A: Alpha Ltd. shall pay within 30 days.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nParty A: Beta Ltd. shall pay within 45 days.",
        ),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days", allow=True),
    )

    party = [item for item in verdict.findings if item.rule_id == "contract-safe.protected.parties"]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(party) == 1
    assert party[0].approvable is False
    assert {item.block_id for item in party[0].evidence.locations} == {
        "block-after-payment",
        "block-before-payment",
    }


def test_repeated_entity_text_is_not_authorized_by_kind_and_value_alone() -> None:
    baseline_text = "Payment obligations\nPay within 30 days or within 30 days."
    candidate_text = "Payment obligations\nPay within 45 days or within 45 days."
    baseline = _contract(_clause("before-payment", baseline_text), sha="a")
    candidate = _contract(_clause("after-payment", candidate_text), sha="b")

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="30 days",
            after="45 days",
            occurrences=2,
            anchor="within",
        ),
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert any(item.rule_id == "contract-safe.protected.durations" for item in verdict.findings)


def test_explicit_protection_omission_does_not_authorize_unrelated_body_change() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nParty A: Alpha Ltd. shall pay within 30 days.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nParty A: Beta Ltd. shall pay within 45 days.",
        ),
        sha="b",
    )
    protect = frozenset(item for item in ProtectedTarget if item is not ProtectedTarget.PARTIES)

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="30 days",
            after="45 days",
            protect=protect,
        ),
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert not any(item.rule_id == "contract-safe.protected.parties" for item in verdict.findings)
    assert any(item.rule_id == "contract-safe.unexplained-clause" for item in verdict.findings)


def _exact_pair(
    *,
    baseline_features: list[DocumentFeature] | None = None,
    candidate_features: list[DocumentFeature] | None = None,
    baseline_regions: list[ProtectedRegion] | None = None,
    candidate_regions: list[ProtectedRegion] | None = None,
    before_evidence: list[EvidenceRef] | None = None,
    after_evidence: list[EvidenceRef] | None = None,
) -> tuple[ContractDocument, ContractDocument]:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nPay within 30 days.",
            evidence=before_evidence,
        ),
        sha="a",
        features=baseline_features,
        regions=baseline_regions,
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nPay within 45 days.",
            evidence=after_evidence,
        ),
        sha="b",
        features=candidate_features,
        regions=candidate_regions,
    )
    return baseline, candidate


def _feature(
    kind: DocumentFeatureKind,
    *,
    fingerprint_value: str = "f" * 64,
    evidence: list[EvidenceRef] | None = None,
    details: dict[str, object] | None = None,
) -> DocumentFeature:
    return DocumentFeature.model_validate(
        {
            "id": f"feature-{kind.value}",
            "kind": kind,
            "fingerprint": fingerprint_value,
            "count": 1,
            "evidence": evidence or [],
            "details": details or {},
        }
    )


@pytest.mark.parametrize(
    "kind",
    [
        DocumentFeatureKind.COMMENT,
        DocumentFeatureKind.TRACKED_REVISION,
        DocumentFeatureKind.HIDDEN_TEXT,
        DocumentFeatureKind.EXTERNAL_LINK,
        DocumentFeatureKind.EMBEDDED_IMAGE,
    ],
)
def test_feature_changes_review_approvably_without_exposing_content(
    kind: DocumentFeatureKind,
) -> None:
    feature_evidence = [EvidenceRef(block_id=f"feature-{kind.value}")]
    feature = _feature(
        kind,
        evidence=feature_evidence,
        details={"content": "SECRET CONTRACT CONTENT"},
    )
    baseline, candidate = _exact_pair(candidate_features=[feature])

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    feature_findings = [item for item in verdict.findings if item.rule_id.endswith(kind.value)]
    assert verdict.outcome is FindingOutcome.REVIEW
    assert len(feature_findings) == 1
    assert feature_findings[0].approvable is True
    assert feature_findings[0].evidence.locations == feature_evidence
    assert b"SECRET CONTRACT CONTENT" not in verdict.canonical_bytes()


def test_feature_evidence_intersecting_protected_region_fails() -> None:
    evidence = [
        EvidenceRef(
            block_id="protected",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=50, y1=20),
        )
    ]
    region = ProtectedRegion(
        id="signature",
        kind=ProtectedRegionKind.SIGNATURE,
        text_fingerprint="s" * 64,
        evidence=evidence,
    )
    feature = _feature(DocumentFeatureKind.COMMENT, evidence=evidence)
    baseline, candidate = _exact_pair(
        candidate_features=[feature],
        baseline_regions=[region],
        candidate_regions=[region.model_copy(update={"id": "candidate-signature"})],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    feature_findings = [item for item in verdict.findings if item.rule_id.endswith("comment")]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(feature_findings) == 1
    assert feature_findings[0].approvable is False


@pytest.mark.parametrize(
    "feature_kind",
    [
        DocumentFeatureKind.COMMENT,
        DocumentFeatureKind.TRACKED_REVISION,
        DocumentFeatureKind.HIDDEN_TEXT,
        DocumentFeatureKind.EXTERNAL_LINK,
        DocumentFeatureKind.EMBEDDED_IMAGE,
    ],
)
@pytest.mark.parametrize(
    "protected_target",
    [
        ProtectedTarget.PARTIES,
        ProtectedTarget.MONEY,
        ProtectedTarget.CURRENCY,
        ProtectedTarget.DATES,
        ProtectedTarget.DURATIONS,
        ProtectedTarget.PERCENTAGES,
    ],
)
def test_feature_block_intersecting_each_protected_entity_kind_fails(
    feature_kind: DocumentFeatureKind,
    protected_target: ProtectedTarget,
) -> None:
    baseline_text = (
        "Payment obligations\nParty A: Alpha Ltd.; on 2026-08-04 shall pay "
        "RMB 10,000.00 within 30 days with a 5% fee."
    )
    candidate_text = baseline_text.replace("30 days", "45 days")
    baseline = _contract(_clause("before-payment", baseline_text), sha="a")
    candidate = _contract(
        _clause("after-payment", candidate_text),
        sha="b",
        features=[
            _feature(
                feature_kind,
                evidence=[EvidenceRef(block_id="block-after-payment")],
            )
        ],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="30 days",
            after="45 days",
            protect=frozenset({protected_target}),
        ),
    )

    feature_findings = [
        item for item in verdict.findings if item.rule_id.endswith(feature_kind.value)
    ]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(feature_findings) == 1
    assert feature_findings[0].approvable is False


def test_feature_bbox_intersecting_protected_entity_fails() -> None:
    entity_box = Rect(x0=20, y0=20, x1=100, y1=40)
    baseline_evidence = [EvidenceRef(block_id="before-entity", page_index=0, bbox=entity_box)]
    candidate_evidence = [EvidenceRef(block_id="after-entity", page_index=0, bbox=entity_box)]
    baseline, candidate = _exact_pair(
        before_evidence=baseline_evidence,
        after_evidence=candidate_evidence,
        candidate_features=[
            _feature(
                DocumentFeatureKind.COMMENT,
                evidence=[
                    EvidenceRef(
                        block_id="different-feature-block",
                        page_index=0,
                        bbox=Rect(x0=30, y0=25, x1=60, y1=35),
                    )
                ],
            )
        ],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="30 days",
            after="45 days",
            protect=frozenset({ProtectedTarget.DURATIONS}),
        ),
    )

    feature = next(
        item for item in verdict.findings if item.rule_id == "contract-safe.feature.comment"
    )
    assert verdict.outcome is FindingOutcome.FAIL
    assert feature.approvable is False


def test_business_or_unknown_metadata_fails() -> None:
    baseline, candidate = _exact_pair(
        candidate_features=[
            _feature(
                DocumentFeatureKind.METADATA,
                details={"metadata_key": "contract_value", "business_relevance": "business"},
            )
        ]
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    metadata = [item for item in verdict.findings if item.rule_id == "contract-safe.metadata"]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(metadata) == 1
    assert metadata[0].approvable is False


@pytest.mark.parametrize(
    ("setting", "outcome", "finding_outcome"),
    [
        ("review", FindingOutcome.REVIEW, FindingOutcome.REVIEW),
        ("ignore", FindingOutcome.PASS, FindingOutcome.PASS),
    ],
)
def test_validated_nonbusiness_metadata_follows_explicit_policy(
    setting: Literal["review", "ignore"],
    outcome: FindingOutcome,
    finding_outcome: FindingOutcome,
) -> None:
    baseline, candidate = _exact_pair(
        candidate_features=[
            _feature(
                DocumentFeatureKind.METADATA,
                details={"metadata_key": "producer", "business_relevance": "non_business"},
            )
        ]
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="30 days",
            after="45 days",
            metadata=MetadataPolicy(non_business_change=setting),
        ),
    )

    metadata = [item for item in verdict.findings if item.rule_id == "contract-safe.metadata"]
    assert verdict.outcome is outcome
    assert len(metadata) == 1
    assert metadata[0].outcome is finding_outcome
    assert metadata[0].approvable is (setting == "review")


def test_ambiguous_candidate_selector_fails_and_is_never_approvable() -> None:
    baseline, candidate = _exact_pair()
    duplicate = candidate.clauses[0].model_copy(update={"id": "after-payment-duplicate"})
    candidate = candidate.model_copy(update={"clauses": [candidate.clauses[0], duplicate]})

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    selectors = [item for item in verdict.findings if ".selector." in item.rule_id]
    assert verdict.outcome is FindingOutcome.FAIL
    assert selectors
    assert all(item.approvable is False for item in selectors)


def test_unresolved_pairing_fails_closed() -> None:
    baseline, candidate = _exact_pair()
    duplicated_before = _clause(
        "duplicate-before-a", "Article III Other\nSame.", label="article iii", heading="Other"
    )
    duplicated_before_2 = duplicated_before.model_copy(update={"id": "duplicate-before-b"})
    duplicated_after = _clause(
        "duplicate-after-a", "Article III Other\nChanged.", label="article iii", heading="Other"
    )
    duplicated_after_2 = duplicated_after.model_copy(update={"id": "duplicate-after-b"})
    baseline = baseline.model_copy(
        update={"clauses": [baseline.clauses[0], duplicated_before, duplicated_before_2]}
    )
    candidate = candidate.model_copy(
        update={"clauses": [candidate.clauses[0], duplicated_after, duplicated_after_2]}
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert any(item.rule_id == "contract-safe.unresolved-clause" for item in verdict.findings)
    assert len([item.id for item in verdict.findings]) == len(
        {item.id for item in verdict.findings}
    )


def test_duplicate_unresolved_occurrences_emit_one_stable_finding_id() -> None:
    baseline, candidate = _exact_pair()
    duplicate = _clause(
        "duplicate-id",
        "Article III Other\nIdentical body.",
        label="article iii",
        heading="Other",
        evidence=[EvidenceRef(block_id="duplicate-first")],
    )
    duplicate_second = duplicate.model_copy(
        update={"evidence": [EvidenceRef(block_id="duplicate-second")]}
    )
    baseline = baseline.model_copy(
        update={"clauses": [*baseline.clauses, duplicate, duplicate_second]}
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    unresolved = [
        item for item in verdict.findings if item.rule_id == "contract-safe.unresolved-clause"
    ]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(unresolved) == 1
    assert len([item.id for item in verdict.findings]) == len(
        {item.id for item in verdict.findings}
    )


def test_policy_and_fact_tampering_fail_integrity_before_policy_rules() -> None:
    baseline, candidate = _exact_pair()
    frozen = _frozen(baseline, before="30 days", after="45 days")
    facts = diff_contracts(baseline, candidate)
    bad_policy = frozen.model_copy(update={"canonical_sha256": "0" * 64})
    bad_facts = facts.model_copy(update={"candidate_sha256": "c" * 64})

    policy_verdict = _evaluate(baseline, candidate, bad_policy, facts=facts)
    fact_verdict = _evaluate(baseline, candidate, frozen, facts=bad_facts)

    for verdict in (policy_verdict, fact_verdict):
        assert verdict.outcome is FindingOutcome.FAIL
        assert verdict.findings
        assert all(item.rule_id.startswith("contract-safe.integrity") for item in verdict.findings)
        assert all(item.approvable is False for item in verdict.findings)


@pytest.mark.parametrize("case", _SEMANTIC_POLICY_BYPASSES)
def test_redigested_semantically_invalid_frozen_policy_fails_at_evaluator_boundary(
    case: str,
) -> None:
    baseline, exact_candidate = _exact_pair()
    candidate = (
        _contract(
            _clause("after-payment", "Payment obligations\nPay within 30 days."),
            sha="b",
        )
        if case == "empty-expect"
        else exact_candidate
    )
    frozen = _frozen(baseline, before="30 days", after="45 days")
    invalid = _redigested_semantically_invalid_frozen(frozen, case)

    verdict = _evaluate(baseline, candidate, invalid)

    assert verdict.outcome is FindingOutcome.FAIL
    assert [finding.rule_id for finding in verdict.findings] == ["contract-safe.integrity.policy"]
    assert all(finding.approvable is False for finding in verdict.findings)


def test_visual_envelope_unions_before_and_after_rendered_boxes() -> None:
    before_evidence = [
        EvidenceRef(
            block_id="before",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=80, y1=30),
        )
    ]
    after_evidence = [
        EvidenceRef(
            block_id="after",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=12, y0=9, x1=82, y1=31),
        )
    ]
    baseline, candidate = _exact_pair(
        before_evidence=before_evidence, after_evidence=after_evidence
    )
    visual = VisualPageChange(
        id="visual-0",
        before_page=0,
        after_page=0,
        changed_pixel_ratio=0.1,
        regions=[Rect(x0=6, y0=4, x1=86, y1=36)],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[visual],
    )

    assert verdict.outcome is FindingOutcome.PASS
    assert any(item.rule_id == "contract-safe.visual.explained" for item in verdict.findings)


def test_disjoint_expected_evidence_does_not_authorize_the_gap_between_boxes() -> None:
    evidence = [
        EvidenceRef(
            block_id="payment-left",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=20, y1=20),
        ),
        EvidenceRef(
            block_id="payment-right",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=80, y0=10, x1=90, y1=20),
        ),
    ]
    baseline, candidate = _exact_pair(before_evidence=evidence, after_evidence=evidence)
    gap = VisualPageChange(
        id="gap",
        before_page=0,
        after_page=0,
        changed_pixel_ratio=0.1,
        regions=[Rect(x0=40, y0=10, x1=50, y1=20)],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[gap],
    )

    assert verdict.outcome is FindingOutcome.REVIEW
    assert any(item.rule_id == "contract-safe.visual.outside-envelope" for item in verdict.findings)


def test_visual_outside_envelope_reviews_approvably() -> None:
    evidence = [
        EvidenceRef(
            block_id="payment",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=80, y1=30),
        )
    ]
    baseline, candidate = _exact_pair(before_evidence=evidence, after_evidence=evidence)
    outside = VisualPageChange(
        id="outside",
        before_page=0,
        after_page=0,
        changed_pixel_ratio=0.1,
        regions=[Rect(x0=100, y0=100, x1=120, y1=120)],
    )
    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[outside],
    )

    visual_findings = [
        item for item in verdict.findings if item.rule_id.startswith("contract-safe.visual")
    ]
    assert verdict.outcome is FindingOutcome.REVIEW
    assert visual_findings
    assert all(item.approvable for item in visual_findings)


def test_deleted_baseline_page_is_a_nonapprovable_fail() -> None:
    baseline, candidate = _exact_pair()
    deleted = VisualPageChange(
        id="deleted",
        before_page=1,
        after_page=None,
        changed_pixel_ratio=1.0,
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[deleted],
    )

    deletion = [
        item for item in verdict.findings if item.rule_id == "contract-safe.visual.page-deletion"
    ]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(deletion) == 1
    assert deletion[0].approvable is False


def test_visual_unavailability_does_not_suppress_known_page_deletion() -> None:
    baseline, candidate = _exact_pair()
    deleted = VisualPageChange(
        id="deleted-unavailable",
        before_page=1,
        after_page=None,
        changed_pixel_ratio=1.0,
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[deleted],
        visual_available=False,
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert {
        item.rule_id for item in verdict.findings if item.rule_id.startswith("contract-safe.visual")
    } == {
        "contract-safe.visual.page-deletion",
        "contract-safe.visual.unavailable",
    }
    assert (
        next(
            item
            for item in verdict.findings
            if item.rule_id == "contract-safe.visual.page-deletion"
        ).approvable
        is False
    )


def test_visual_change_over_protected_rendered_region_fails() -> None:
    payment_evidence = [
        EvidenceRef(
            block_id="payment",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=80, y1=30),
        )
    ]
    protected_evidence = [
        EvidenceRef(
            block_id="signature",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=100, y0=100, x1=150, y1=130),
        )
    ]
    region = ProtectedRegion(
        id="signature",
        kind=ProtectedRegionKind.SIGNATURE,
        text_fingerprint="s" * 64,
        evidence=protected_evidence,
    )
    baseline, candidate = _exact_pair(
        before_evidence=payment_evidence,
        after_evidence=payment_evidence,
        baseline_regions=[region],
        candidate_regions=[region.model_copy(update={"id": "signature-after"})],
    )
    visual = VisualPageChange(
        id="protected",
        before_page=0,
        after_page=0,
        changed_pixel_ratio=0.1,
        regions=[Rect(x0=110, y0=105, x1=120, y1=115)],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[visual],
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert any(item.rule_id == "contract-safe.visual.protected" for item in verdict.findings)


def test_visual_unavailability_does_not_suppress_known_protected_change() -> None:
    payment_evidence = [
        EvidenceRef(
            block_id="payment",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=80, y1=30),
        )
    ]
    protected_evidence = [
        EvidenceRef(
            block_id="signature",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=100, y0=100, x1=150, y1=130),
        )
    ]
    region = ProtectedRegion(
        id="signature",
        kind=ProtectedRegionKind.SIGNATURE,
        text_fingerprint="s" * 64,
        evidence=protected_evidence,
    )
    baseline, candidate = _exact_pair(
        before_evidence=payment_evidence,
        after_evidence=payment_evidence,
        baseline_regions=[region],
        candidate_regions=[region.model_copy(update={"id": "signature-after"})],
    )
    visual = VisualPageChange(
        id="protected-unavailable",
        before_page=0,
        after_page=0,
        changed_pixel_ratio=0.1,
        regions=[Rect(x0=110, y0=105, x1=120, y1=115)],
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_changes=[visual],
        visual_available=False,
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert {
        item.rule_id for item in verdict.findings if item.rule_id.startswith("contract-safe.visual")
    } == {
        "contract-safe.visual.protected",
        "contract-safe.visual.unavailable",
    }
    assert (
        next(
            item for item in verdict.findings if item.rule_id == "contract-safe.visual.protected"
        ).approvable
        is False
    )


def test_finding_order_ids_and_bytes_are_stable_under_fact_and_visual_permutations() -> None:
    evidence = [
        EvidenceRef(
            block_id="payment",
            rendered_page_index=0,
            rendered_bbox=Rect(x0=10, y0=10, x1=80, y1=30),
        )
    ]
    baseline, candidate = _exact_pair(before_evidence=evidence, after_evidence=evidence)
    frozen = _frozen(baseline, before="30 days", after="45 days")
    facts = diff_contracts(baseline, candidate)
    permuted_facts = facts.model_copy(
        update={
            "clause_changes": list(reversed(facts.clause_changes)),
            "entity_changes": list(reversed(facts.entity_changes)),
            "region_changes": list(reversed(facts.region_changes)),
            "feature_changes": list(reversed(facts.feature_changes)),
            "unresolved_clause_ids": list(reversed(facts.unresolved_clause_ids)),
        }
    )
    visuals = [
        VisualPageChange(
            id="b",
            before_page=0,
            after_page=0,
            changed_pixel_ratio=0.1,
            regions=[Rect(x0=100, y0=100, x1=110, y1=110)],
        ),
        VisualPageChange(
            id="a",
            before_page=0,
            after_page=0,
            changed_pixel_ratio=0.1,
            regions=[Rect(x0=120, y0=120, x1=130, y1=130)],
        ),
    ]

    ordered = _evaluate(baseline, candidate, frozen, facts=facts, visual_changes=visuals)
    permuted = _evaluate(
        baseline,
        candidate,
        frozen,
        facts=permuted_facts,
        visual_changes=list(reversed(visuals)),
    )

    assert ordered.canonical_bytes() == permuted.canonical_bytes()
    assert [item.id for item in ordered.findings] == [item.id for item in permuted.findings]


def test_multiple_independent_expected_operations_in_one_clause_pass() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nPay USD 100 within 30 days.",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nPay EUR 100 within 45 days.",
        ),
        sha="b",
    )
    clause = baseline.clauses[0]
    selector = ClauseSelector(
        clause_label=clause.label.normalized,
        heading=clause.heading,
        anchor="Payment obligations",
        baseline_fingerprint=clause.fingerprint,
    )
    policy = ContractPolicy(
        baseline=PolicyBaseline(sha256=baseline.source.sha256, format="docx"),
        expect=[
            ExpectedRule(
                id="currency",
                selector=selector,
                operation=ExactReplace(before="USD", after="EUR"),
            ),
            ExpectedRule(
                id="window",
                selector=selector,
                operation=ExactReplace(before="30 days", after="45 days"),
            ),
        ],
    )

    verdict = _evaluate(baseline, candidate, freeze_policy(baseline, policy))

    assert verdict.outcome is FindingOutcome.PASS
    assert len([item for item in verdict.findings if ".expected." in item.rule_id]) == 2


def test_crossed_independent_expected_operations_fail_nonapprovably() -> None:
    baseline = _contract(
        _clause("before-payment", "Payment obligations\nFirst RED; second YELLOW."),
        sha="a",
    )
    candidate = _contract(
        _clause("after-payment", "Payment obligations\nFirst GREEN; second BLUE."),
        sha="b",
    )
    clause = baseline.clauses[0]
    selector = ClauseSelector(
        clause_label=clause.label.normalized,
        heading=clause.heading,
        anchor="Payment obligations",
        baseline_fingerprint=clause.fingerprint,
    )
    policy = ContractPolicy(
        baseline=PolicyBaseline(sha256=baseline.source.sha256, format="docx"),
        expect=[
            ExpectedRule(
                id="first",
                selector=selector,
                operation=ExactReplace(before="RED", after="BLUE"),
            ),
            ExpectedRule(
                id="second",
                selector=selector,
                operation=ExactReplace(before="YELLOW", after="GREEN"),
            ),
        ],
        allow=[AllowRule(selector=selector, kinds=frozenset({"modified"}))],
    )

    verdict = _evaluate(baseline, candidate, freeze_policy(baseline, policy))

    expected = [item for item in verdict.findings if ".expected." in item.rule_id]
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected
    assert any(item.outcome is FindingOutcome.FAIL for item in expected)
    assert all(not item.approvable for item in expected if item.outcome is FindingOutcome.FAIL)


def test_every_protected_entity_kind_outside_authorized_span_fails() -> None:
    baseline_text = (
        "Agreement details\ncommercial terms. Party A: Alpha Ltd.; pay USD 100 on "
        "2026-08-04 within 30 days with a 5% fee."
    )
    candidate_text = (
        "Agreement details\nrevised commercial terms. Party A: Beta Ltd.; pay EUR 200 on "
        "2026-09-05 within 45 days with a 7% fee."
    )
    baseline = _contract(_clause("before-payment", baseline_text), sha="a")
    candidate = _contract(_clause("after-payment", candidate_text), sha="b")

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="commercial terms",
            after="revised commercial terms",
            anchor="Agreement details",
        ),
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert {
        item.rule_id
        for item in verdict.findings
        if item.rule_id.startswith("contract-safe.protected")
    } == {
        "contract-safe.protected.parties",
        "contract-safe.protected.money",
        "contract-safe.protected.currency",
        "contract-safe.protected.dates",
        "contract-safe.protected.durations",
        "contract-safe.protected.percentages",
    }


def test_every_changed_protected_region_kind_fails() -> None:
    baseline_regions = [
        ProtectedRegion(
            id=f"before-{kind.value}",
            kind=kind,
            text_fingerprint="a" * 64,
        )
        for kind in ProtectedRegionKind
    ]
    candidate_regions = [
        ProtectedRegion(
            id=f"after-{kind.value}",
            kind=kind,
            text_fingerprint="b" * 64,
        )
        for kind in ProtectedRegionKind
    ]
    baseline, candidate = _exact_pair(
        baseline_regions=baseline_regions,
        candidate_regions=candidate_regions,
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert {
        item.rule_id
        for item in verdict.findings
        if item.rule_id.startswith("contract-safe.protected")
    } == {
        "contract-safe.protected.headers",
        "contract-safe.protected.footers",
        "contract-safe.protected.signatures",
        "contract-safe.protected.seals",
        "contract-safe.protected.attachments",
    }


def test_missing_visual_defaults_to_approvable_review_through_evaluator() -> None:
    baseline, candidate = _exact_pair()

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="30 days", after="45 days"),
        visual_available=False,
    )

    unavailable = [
        item for item in verdict.findings if item.rule_id == "contract-safe.visual.unavailable"
    ]
    assert verdict.outcome is FindingOutcome.REVIEW
    assert len(unavailable) == 1
    assert unavailable[0].approvable is True


def test_deleted_baseline_page_fails_even_with_review_pagination_policy() -> None:
    baseline, candidate = _exact_pair()
    unpaired = VisualPageChange(
        id="unpaired",
        before_page=1,
        after_page=None,
        changed_pixel_ratio=1.0,
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(
            baseline,
            before="30 days",
            after="45 days",
            visual=VisualPolicy(pagination_reflow="review"),
        ),
        visual_changes=[unpaired],
    )

    deletion = [
        item for item in verdict.findings if item.rule_id == "contract-safe.visual.page-deletion"
    ]
    assert verdict.outcome is FindingOutcome.FAIL
    assert len(deletion) == 1
    assert deletion[0].approvable is False


def test_tampered_fact_content_fails_even_when_source_hashes_match() -> None:
    baseline, candidate = _exact_pair()
    frozen = _frozen(baseline, before="30 days", after="45 days")
    facts = diff_contracts(baseline, candidate)
    tampered = facts.model_copy(update={"clause_changes": []})

    verdict = _evaluate(baseline, candidate, frozen, facts=tampered)

    assert verdict.outcome is FindingOutcome.FAIL
    assert [item.rule_id for item in verdict.findings] == ["contract-safe.integrity.facts"]


@pytest.mark.parametrize("side", ["baseline", "candidate"])
@pytest.mark.parametrize("unsafe", [False, True])
def test_malformed_contract_documents_fail_integrity_without_raising(
    side: Literal["baseline", "candidate"], unsafe: bool
) -> None:
    baseline, candidate = _exact_pair()
    frozen = _frozen(baseline, before="30 days", after="45 days")
    facts = diff_contracts(baseline, candidate)
    malformed: object = (
        baseline.model_copy(update={"source": None})
        if side == "baseline"
        else candidate.model_copy(update={"source": None})
    )
    if not unsafe:
        malformed = {"source": None}
    left = malformed if side == "baseline" else baseline
    right = malformed if side == "candidate" else candidate

    first = evaluate_contract(
        frozen,
        left,  # type: ignore[arg-type]
        right,  # type: ignore[arg-type]
        facts,
        [],
        True,
    )
    second = evaluate_contract(
        frozen,
        left,  # type: ignore[arg-type]
        right,  # type: ignore[arg-type]
        facts,
        [],
        True,
    )

    assert first.outcome is FindingOutcome.FAIL
    assert [item.rule_id for item in first.findings] == [f"contract-safe.integrity.{side}-document"]
    assert all(item.approvable is False for item in first.findings)
    assert first.canonical_bytes() == second.canonical_bytes()


def test_malformed_visual_fact_fails_integrity_instead_of_raising() -> None:
    baseline, candidate = _exact_pair()
    frozen = _frozen(baseline, before="30 days", after="45 days")

    verdict = evaluate_contract(
        frozen,
        baseline,
        candidate,
        diff_contracts(baseline, candidate),
        [{"id": "incomplete"}],  # type: ignore[list-item]
        True,
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert [item.rule_id for item in verdict.findings] == ["contract-safe.integrity.visual-input"]


def test_excessive_visual_findings_collapse_to_one_bounded_failure() -> None:
    baseline, candidate = _exact_pair()
    frozen = _frozen(baseline, before="30 days", after="45 days")
    visual_changes = [
        VisualPageChange(
            id=f"page-{index:04d}",
            before_page=index,
            after_page=None,
            changed_pixel_ratio=1.0,
        )
        for index in range(1_001)
    ]

    verdict = _evaluate(
        baseline,
        candidate,
        frozen,
        visual_changes=visual_changes,
    )

    assert verdict.outcome is FindingOutcome.FAIL
    assert len(verdict.findings) <= 1_000
    assert any(
        item.rule_id == "contract-safe.integrity.findings-limit" for item in verdict.findings
    )
