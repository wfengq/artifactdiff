import pytest
from pydantic import ValidationError

import artifactdiff
import artifactdiff.contract as contract_api
from artifactdiff.contract.models import (
    ClauseLabel,
    ContractClause,
    ContractDocument,
    LanguageKind,
    LanguageProfile,
)
from artifactdiff.contract.selectors import (
    ClauseSelector,
    SelectorMatch,
    SelectorResolution,
    SelectorResolutionStatus,
    resolve_baseline,
    resolve_candidate,
)
from artifactdiff.models import SourceDescriptor
from artifactdiff.normalize import fingerprint, normalize_text


def _clause(
    clause_id: str,
    *,
    label: str,
    heading: str,
    text: str,
    ancestor_path: tuple[str, ...] = (),
    content_fingerprint: str | None = None,
) -> ContractClause:
    return ContractClause(
        id=clause_id,
        label=ClauseLabel(printed=label, normalized=normalize_text(label), scheme="section"),
        heading=heading,
        ancestor_path=ancestor_path,
        text=text,
        normalized_text=normalize_text(text),
        fingerprint=content_fingerprint or fingerprint(text),
    )


def _contract(*clauses: ContractClause) -> ContractDocument:
    return ContractDocument(
        source=SourceDescriptor(
            path="contract.pdf", sha256="a" * 64, format="pdf", size_bytes=1
        ),
        language=LanguageProfile(kind=LanguageKind.BILINGUAL),
        clauses=list(clauses),
    )


def test_selector_types_are_public_contract_interfaces() -> None:
    assert contract_api.ClauseSelector is ClauseSelector
    assert contract_api.SelectorResolution is SelectorResolution
    assert artifactdiff.ClauseSelector is ClauseSelector
    assert artifactdiff.SelectorResolution is SelectorResolution


def test_selector_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ClauseSelector.model_validate(
            {
                "clause_label": "Section 4",
                "heading": "Payment",
                "anchor": "within 30 days",
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        SelectorMatch.model_validate(
            {"clause_id": "clause-1", "score": 1.0, "unexpected": True}
        )
    with pytest.raises(ValidationError):
        SelectorResolution.model_validate(
            {"status": "missing", "matches": [], "unexpected": True}
        )


def test_baseline_requires_one_exact_normalized_identity_match() -> None:
    selected = _clause(
        "clause-payment",
        label="第四条",
        heading="付款条件",
        ancestor_path=("主协议",),
        text="第四条 付款条件\n发票开具后 30 天内付款",
    )
    document = _contract(
        _clause(
            "clause-other",
            label="第三条",
            heading="交付",
            ancestor_path=("主协议",),
            text="第三条 交付\n30 天内交付",
        ),
        selected,
    )
    selector = ClauseSelector(
        clause_label="第四条",
        heading="付款条件",
        ancestor_path=("主协议",),
        anchor="发票开具后　30 天内付款",
        baseline_fingerprint=selected.fingerprint,
    )

    resolution = resolve_baseline(document, selector)

    assert resolution.status is SelectorResolutionStatus.UNIQUE
    assert resolution.matcher_version == "1.0"
    assert resolution.matches == [SelectorMatch(clause_id="clause-payment", score=1.0)]


@pytest.mark.parametrize(
    ("changed_field", "expected_status"),
    [
        ("fingerprint", SelectorResolutionStatus.MISSING),
        ("occurrences", SelectorResolutionStatus.MISSING),
        ("duplicate", SelectorResolutionStatus.AMBIGUOUS),
    ],
)
def test_baseline_fails_closed_for_changed_or_duplicated_identity(
    changed_field: str, expected_status: SelectorResolutionStatus
) -> None:
    first = _clause(
        "clause-b",
        label="Section 4",
        heading="Payment",
        text="Section 4 Payment\nPayment is due within 30 days",
        content_fingerprint="baseline-fingerprint",
    )
    clauses = [first]
    fingerprint_value = "baseline-fingerprint"
    occurrences = 1
    if changed_field == "fingerprint":
        fingerprint_value = "different-fingerprint"
    elif changed_field == "occurrences":
        occurrences = 2
    else:
        clauses.append(first.model_copy(update={"id": "clause-a"}))
    selector = ClauseSelector(
        clause_label="section 4",
        heading="PAYMENT",
        anchor="payment is due within 30 days",
        baseline_fingerprint=fingerprint_value,
        occurrences=occurrences,
    )

    resolution = resolve_baseline(_contract(*clauses), selector)

    assert resolution.status is expected_status
    assert [match.clause_id for match in resolution.matches] == (
        ["clause-a", "clause-b"]
        if expected_status is SelectorResolutionStatus.AMBIGUOUS
        else []
    )


@pytest.mark.parametrize(
    ("label", "heading", "ancestor_path", "text"),
    [
        ("第四条", "付款条件", ("主协议",), "发票后 30 天内付款"),
        ("Section 4", "Payment Terms", ("Agreement",), "Payment within 30 days"),
        (
            "第四条 Section 4",
            "Payment Terms 付款条件",
            ("Agreement 主协议",),
            "Payment 应在 30 days 天内完成",
        ),
    ],
)
def test_candidate_resolves_chinese_english_and_bilingual_identity_drift(
    label: str, heading: str, ancestor_path: tuple[str, ...], text: str
) -> None:
    candidate = _clause(
        "clause-payment",
        label=label.swapcase(),
        heading=heading.swapcase(),
        ancestor_path=tuple(item.swapcase() for item in ancestor_path),
        text=f"{heading}\n{text.replace(' 30 ', '   30  ')}",
    )
    selector = ClauseSelector(
        clause_label=label,
        heading=heading,
        ancestor_path=ancestor_path,
        anchor=text,
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.HIGH_CONFIDENCE
    assert resolution.matches == [SelectorMatch(clause_id="clause-payment", score=1.0)]


def test_candidate_excludes_label_and_ancestor_mismatches() -> None:
    document = _contract(
        _clause(
            "wrong-label",
            label="Section 5",
            heading="Payment",
            ancestor_path=("Agreement",),
            text="within 30 days",
        ),
        _clause(
            "wrong-ancestor",
            label="Section 4",
            heading="Payment",
            ancestor_path=("Schedule",),
            text="within 30 days",
        ),
    )
    selector = ClauseSelector(
        clause_label="Section 4",
        heading="Payment",
        ancestor_path=("Agreement",),
        anchor="within 30 days",
    )

    resolution = resolve_candidate(document, selector)

    assert resolution.status is SelectorResolutionStatus.MISSING
    assert resolution.matches == []


def test_candidate_tie_is_ambiguous_and_diagnostics_sort_by_clause_id() -> None:
    selector = ClauseSelector(
        clause_label="4.2", heading="Payment", anchor="within 30 days"
    )
    document = _contract(
        _clause(
            "clause-z", label="4.2", heading="Payment", text="Pay within 30 days"
        ),
        _clause(
            "clause-a", label="4.2", heading="Payment", text="Pay within 30 days"
        ),
    )

    resolution = resolve_candidate(document, selector)

    assert resolution.status is SelectorResolutionStatus.AMBIGUOUS
    assert resolution.matches == [
        SelectorMatch(clause_id="clause-a", score=1.0),
        SelectorMatch(clause_id="clause-z", score=1.0),
    ]


def test_candidate_tie_stays_ambiguous_when_minimum_margin_is_zero() -> None:
    selector = ClauseSelector(
        clause_label="4.2",
        heading="Payment",
        anchor="within 30 days",
        min_margin=0.0,
    )
    document = _contract(
        _clause(
            "clause-b", label="4.2", heading="Payment", text="within 30 days"
        ),
        _clause(
            "clause-a", label="4.2", heading="Payment", text="within 30 days"
        ),
    )

    resolution = resolve_candidate(document, selector)

    assert resolution.status is SelectorResolutionStatus.AMBIGUOUS


@pytest.mark.parametrize(
    ("min_similarity", "expected_status"),
    [
        (0.95, SelectorResolutionStatus.HIGH_CONFIDENCE),
        (0.950001, SelectorResolutionStatus.MISSING),
    ],
)
def test_candidate_similarity_threshold_is_inclusive(
    min_similarity: float, expected_status: SelectorResolutionStatus
) -> None:
    candidate = _clause(
        "clause-1", label="4.2", heading="abcdf", text="within 30 days"
    )
    selector = ClauseSelector(
        clause_label="4.2",
        heading="abcde",
        anchor="within 30 days",
        min_similarity=min_similarity,
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is expected_status
    assert resolution.matches == [SelectorMatch(clause_id="clause-1", score=0.95)]


@pytest.mark.parametrize(
    ("min_margin", "expected_status"),
    [
        (0.05, SelectorResolutionStatus.HIGH_CONFIDENCE),
        (0.050001, SelectorResolutionStatus.AMBIGUOUS),
    ],
)
def test_candidate_runner_up_margin_is_inclusive(
    min_margin: float, expected_status: SelectorResolutionStatus
) -> None:
    document = _contract(
        _clause(
            "clause-best", label="4.2", heading="abcde", text="within 30 days"
        ),
        _clause(
            "clause-runner", label="4.2", heading="abcdf", text="within 30 days"
        ),
    )
    selector = ClauseSelector(
        clause_label="4.2",
        heading="abcde",
        anchor="within 30 days",
        min_margin=min_margin,
    )

    resolution = resolve_candidate(document, selector)

    assert resolution.status is expected_status
    assert resolution.matches == [
        SelectorMatch(clause_id="clause-best", score=1.0),
        SelectorMatch(clause_id="clause-runner", score=0.95),
    ]


def test_candidate_relocates_one_expected_anchor_value_edit() -> None:
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="Payment is due within 30 days",
        baseline_fingerprint="baseline-fingerprint",
    )
    candidate = _clause(
        "clause-payment",
        label="Article II",
        heading="Payment Terms",
        text="Article II Payment Terms\nPayment is due within 45 days",
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.HIGH_CONFIDENCE
    assert resolution.matches[0].score >= selector.min_similarity


def test_candidate_relocates_short_numeric_anchor_inside_longer_line() -> None:
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="within 30 days",
    )
    candidate = _clause(
        "clause-payment",
        label="Article II",
        heading="Payment Terms",
        text="Party A shall make payment within 45 days after invoice",
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.HIGH_CONFIDENCE


@pytest.mark.parametrize(
    "candidate_text",
    [
        "45",
        "99",
        "999999",
        "Unrelated audit cap is 999999 records",
    ],
)
def test_candidate_rejects_changed_numeric_only_anchor(
    candidate_text: str,
) -> None:
    baseline = _clause(
        "clause-baseline",
        label="Article II",
        heading="Payment Terms",
        text="30",
    )
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="30",
        baseline_fingerprint=baseline.fingerprint,
    )
    candidate = _clause(
        "clause-candidate",
        label="Article II",
        heading="Payment Terms",
        text=candidate_text,
    )

    baseline_resolution = resolve_baseline(_contract(baseline), selector)
    candidate_resolution = resolve_candidate(_contract(candidate), selector)

    assert baseline_resolution.status is SelectorResolutionStatus.UNIQUE
    assert candidate_resolution.status is SelectorResolutionStatus.MISSING
    assert candidate_resolution.matches == [
        SelectorMatch(clause_id="clause-candidate", score=0.75)
    ]


def test_candidate_rejects_changed_numeric_anchor_with_only_punctuation_context() -> None:
    baseline = _clause(
        "clause-baseline",
        label="Article II",
        heading="Payment Terms",
        text="--- 30 !!!",
    )
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="--- 30 !!!",
        baseline_fingerprint=baseline.fingerprint,
    )
    candidate = _clause(
        "clause-candidate",
        label="Article II",
        heading="Payment Terms",
        text="--- 45 !!!",
    )

    assert (
        resolve_baseline(_contract(baseline), selector).status
        is SelectorResolutionStatus.UNIQUE
    )
    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.MISSING
    assert resolution.matches[0].score == 0.75


def test_candidate_rejects_unrelated_contextual_number() -> None:
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="within 30 days",
    )
    candidate = _clause(
        "clause-candidate",
        label="Article II",
        heading="Payment Terms",
        text="Unrelated audit cap is 999999 records",
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.MISSING
    assert resolution.matches[0].score == 0.75


@pytest.mark.parametrize(
    "candidate_text",
    [
        "Payment is due within 45 days with a 7 percent fee",
        "Payment is due within 999999 days with a 5 percent fee",
    ],
)
def test_candidate_rejects_incompatible_numeric_token_edits(
    candidate_text: str,
) -> None:
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="Payment is due within 30 days with a 5 percent fee",
    )
    candidate = _clause(
        "clause-candidate",
        label="Article II",
        heading="Payment Terms",
        text=candidate_text,
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.MISSING
    assert resolution.matches[0].score == 0.75


def test_candidate_rejects_duplicate_fuzzy_anchor_occurrences() -> None:
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="Payment is due within 30 days",
        occurrences=1,
    )
    candidate = _clause(
        "clause-payment",
        label="Article II",
        heading="Payment Terms",
        text=(
            "Article II Payment Terms\n"
            "Payment is due within 45 days\n"
            "Payment is due within 46 days"
        ),
    )

    resolution = resolve_candidate(_contract(candidate), selector)

    assert resolution.status is SelectorResolutionStatus.MISSING
    assert resolution.matches[0].score == 0.75


def test_candidate_fuzzy_anchor_tie_remains_ambiguous() -> None:
    selector = ClauseSelector(
        clause_label="Article II",
        heading="Payment Terms",
        anchor="within 30 days",
    )
    document = _contract(
        _clause(
            "clause-b",
            label="Article II",
            heading="Payment Terms",
            text="Payment is due within 45 days after invoice",
        ),
        _clause(
            "clause-a",
            label="Article II",
            heading="Payment Terms",
            text="Payment is due within 46 days after invoice",
        ),
    )

    resolution = resolve_candidate(document, selector)

    assert resolution.status is SelectorResolutionStatus.AMBIGUOUS
    assert [match.clause_id for match in resolution.matches] == [
        "clause-a",
        "clause-b",
    ]
