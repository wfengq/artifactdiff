from __future__ import annotations

from typing import Literal

import pytest
from pydantic import ValidationError

from artifactdiff.contract.entities import extract_entities
from artifactdiff.contract.models import (
    ClauseLabel,
    ContractClause,
    ContractDocument,
    DocumentFeature,
    DocumentFeatureKind,
    EvidenceRef,
    LanguageKind,
    LanguageProfile,
    ProtectedRegion,
    ProtectedRegionKind,
)
from artifactdiff.models import SourceDescriptor
from artifactdiff.normalize import fingerprint, normalize_text
from artifactdiff.verification import (
    ClauseChange,
    ClauseChangeKind,
    ContractChangeSet,
    diff_contracts,
)


def _clause(
    clause_id: str,
    text: str,
    *,
    label: str = "article ii",
    heading: str = "Payment Terms",
    ancestor_path: tuple[str, ...] = (),
    block_id: str | None = None,
) -> ContractClause:
    evidence = EvidenceRef(block_id=block_id or f"block-{clause_id}")
    entities = extract_entities(text, clause_id, evidence)
    return ContractClause(
        id=clause_id,
        label=ClauseLabel(printed=label, normalized=label, scheme="article"),
        heading=heading,
        ancestor_path=ancestor_path,
        text=text,
        normalized_text=normalize_text(text),
        fingerprint=fingerprint(text),
        evidence=[evidence],
        entities=entities,
    )


def _contract(
    *clauses: ContractClause,
    sha: str = "a",
    format: Literal["docx", "pdf"] = "docx",
) -> ContractDocument:
    return ContractDocument(
        source=SourceDescriptor(
            path=f"contract.{format}",
            sha256=sha * 64,
            format=format,
            size_bytes=1,
        ),
        language=LanguageProfile(kind=LanguageKind.ENGLISH),
        clauses=list(clauses),
        entities=[entity for clause in clauses for entity in clause.entities],
    )


def _payment_text(days: int) -> str:
    return f"Article II Payment Terms\nParty A shall pay within {days} days."


def _feature(
    identifier: str,
    kind: DocumentFeatureKind,
    value: str,
    *,
    details: dict[str, object] | None = None,
    count: int = 1,
) -> DocumentFeature:
    return DocumentFeature.model_validate(
        {
            "id": identifier,
            "kind": kind,
            "fingerprint": value,
            "count": count,
            "details": details or {},
        }
    )


def test_diff_contracts_records_exact_payment_text_and_duration_change() -> None:
    baseline = _contract(_clause("baseline-payment", _payment_text(30)))
    candidate = _contract(_clause("candidate-payment", _payment_text(45)), sha="b")

    facts = diff_contracts(baseline, candidate)

    assert len(facts.clause_changes) == 1
    change = facts.clause_changes[0]
    assert change.kind is ClauseChangeKind.MODIFIED
    assert (change.before_text, change.after_text) == (_payment_text(30), _payment_text(45))
    assert {
        (item.kind.value, item.before_value, item.after_value) for item in facts.entity_changes
    } == {("duration", "30 day", "45 day")}


def test_diff_contracts_keeps_duplicate_identity_and_fingerprint_ties_unresolved() -> None:
    shared_fingerprint = "f" * 64
    baseline = _contract(
        _clause("baseline-one", "Article II Payment Terms\nFirst version.").model_copy(
            update={"fingerprint": shared_fingerprint}
        ),
        _clause("baseline-two", "Article II Payment Terms\nSecond version.").model_copy(
            update={"fingerprint": shared_fingerprint}
        ),
    )
    candidate = _contract(
        _clause("candidate-one", "Article II Payment Terms\nChanged first.").model_copy(
            update={"fingerprint": shared_fingerprint}
        ),
        _clause("candidate-two", "Article II Payment Terms\nChanged second.").model_copy(
            update={"fingerprint": shared_fingerprint}
        ),
        sha="b",
    )

    facts = diff_contracts(baseline, candidate)

    assert facts.clause_changes == []
    assert facts.unresolved_clause_ids == [
        "baseline-one",
        "baseline-two",
        "candidate-one",
        "candidate-two",
    ]


def test_same_fingerprint_duplicates_only_before_are_all_removed_with_evidence() -> None:
    shared_fingerprint = "f" * 64
    first_evidence = EvidenceRef(block_id="before-a")
    second_evidence = EvidenceRef(block_id="before-b")
    first = _clause(
        "baseline-a",
        "Article I Parties\nShared body.",
        label="article i",
        heading="Parties",
    ).model_copy(update={"fingerprint": shared_fingerprint, "evidence": [first_evidence]})
    second = _clause(
        "baseline-b",
        "Article II Payment\nShared body.",
        label="article ii",
        heading="Payment",
    ).model_copy(update={"fingerprint": shared_fingerprint, "evidence": [second_evidence]})

    facts = diff_contracts(_contract(first, second), _contract(sha="b"))

    assert facts.unresolved_clause_ids == []
    assert {
        (item.kind, item.before_clause_id, item.before_text, item.before_evidence[0].block_id)
        for item in facts.clause_changes
    } == {
        (ClauseChangeKind.REMOVED, "baseline-a", first.text, "before-a"),
        (ClauseChangeKind.REMOVED, "baseline-b", second.text, "before-b"),
    }


def test_same_fingerprint_duplicates_only_after_are_all_added_with_evidence() -> None:
    shared_fingerprint = "f" * 64
    first = _clause(
        "candidate-a",
        "Article I Parties\nShared body.",
        label="article i",
        heading="Parties",
        block_id="after-a",
    ).model_copy(update={"fingerprint": shared_fingerprint})
    second = _clause(
        "candidate-b",
        "Article II Payment\nShared body.",
        label="article ii",
        heading="Payment",
        block_id="after-b",
    ).model_copy(update={"fingerprint": shared_fingerprint})

    facts = diff_contracts(_contract(), _contract(first, second, sha="b"))

    assert facts.unresolved_clause_ids == []
    assert {
        (item.kind, item.after_clause_id, item.after_text, item.after_evidence[0].block_id)
        for item in facts.clause_changes
    } == {
        (ClauseChangeKind.ADDED, "candidate-a", first.text, "after-a"),
        (ClauseChangeKind.ADDED, "candidate-b", second.text, "after-b"),
    }


def test_duplicate_identity_on_only_one_side_is_not_ambiguous() -> None:
    first = _clause("baseline-a", "Article II Payment Terms\nFirst body.")
    second = _clause("baseline-b", "Article II Payment Terms\nSecond body.")

    facts = diff_contracts(_contract(first, second), _contract(sha="b"))

    assert facts.unresolved_clause_ids == []
    assert {(item.kind, item.before_clause_id) for item in facts.clause_changes} == {
        (ClauseChangeKind.REMOVED, "baseline-a"),
        (ClauseChangeKind.REMOVED, "baseline-b"),
    }

    symmetric = diff_contracts(
        _contract(),
        _contract(
            first.model_copy(update={"id": "candidate-a"}),
            second.model_copy(update={"id": "candidate-b"}),
            sha="b",
        ),
    )

    assert symmetric.unresolved_clause_ids == []
    assert {(item.kind, item.after_clause_id) for item in symmetric.clause_changes} == {
        (ClauseChangeKind.ADDED, "candidate-a"),
        (ClauseChangeKind.ADDED, "candidate-b"),
    }


def test_unique_identities_disambiguate_duplicate_fingerprints_before_fallback() -> None:
    shared_fingerprint = "f" * 64
    first_before = _clause(
        "baseline-a", "Article I Parties\nShared body.", label="article i", heading="Parties"
    ).model_copy(update={"fingerprint": shared_fingerprint})
    second_before = _clause(
        "baseline-b",
        "Article II Payment\nShared body.",
        label="article ii",
        heading="Payment",
    ).model_copy(update={"fingerprint": shared_fingerprint})
    first_after = first_before.model_copy(update={"id": "candidate-a"})
    second_after = second_before.model_copy(update={"id": "candidate-b"})

    facts = diff_contracts(
        _contract(first_before, second_before),
        _contract(first_after, second_after, sha="b"),
    )

    assert facts.clause_changes == []
    assert facts.unresolved_clause_ids == []


def test_unique_fingerprint_pair_disambiguates_one_sided_duplicate_identity() -> None:
    paired = _clause("baseline-paired", "Article II Payment Terms\nExact body.")
    removed = _clause("baseline-removed", "Article II Payment Terms\nRemoved body.")
    candidate_pair = paired.model_copy(update={"id": "candidate-paired"})

    facts = diff_contracts(_contract(paired, removed), _contract(candidate_pair, sha="b"))

    assert facts.unresolved_clause_ids == []
    assert [
        (item.kind, item.before_clause_id, item.after_clause_id) for item in facts.clause_changes
    ] == [(ClauseChangeKind.REMOVED, "baseline-removed", None)]


def test_one_sided_duplicate_classification_is_permutation_stable() -> None:
    shared_fingerprint = "f" * 64
    first = _clause(
        "baseline-a", "Article I Parties\nShared body.", label="article i", heading="Parties"
    ).model_copy(update={"fingerprint": shared_fingerprint})
    second = _clause(
        "baseline-b",
        "Article II Payment\nShared body.",
        label="article ii",
        heading="Payment",
    ).model_copy(update={"fingerprint": shared_fingerprint})

    ordered = diff_contracts(_contract(first, second), _contract(sha="b"))
    permuted = diff_contracts(_contract(second, first), _contract(sha="b"))

    assert ordered.model_dump_json() == permuted.model_dump_json()


def test_clause_evidence_order_does_not_change_fact_bytes() -> None:
    first = EvidenceRef(block_id="stable-a", page_index=0)
    second = EvidenceRef(block_id="stable-b", page_index=1)
    baseline_clause = _clause("baseline", _payment_text(30)).model_copy(
        update={"evidence": [first, second]}
    )
    candidate_clause = _clause("candidate", _payment_text(45)).model_copy(
        update={"evidence": [first, second]}
    )
    permuted_baseline = baseline_clause.model_copy(update={"evidence": [second, first]})
    permuted_candidate = candidate_clause.model_copy(update={"evidence": [second, first]})

    first_run = diff_contracts(_contract(baseline_clause), _contract(candidate_clause, sha="b"))
    permuted_run = diff_contracts(
        _contract(permuted_baseline), _contract(permuted_candidate, sha="b")
    )

    assert first_run.model_dump_json() == permuted_run.model_dump_json()


def test_diff_contracts_emits_unique_added_and_removed_clauses() -> None:
    kept_before = _clause(
        "kept-before", "Article I Parties\nStable.", label="article i", heading="Parties"
    )
    kept_after = _clause(
        "kept-after", "Article I Parties\nStable.", label="article i", heading="Parties"
    )
    removed = _clause(
        "removed", "Article II Payment\nRemoved.", label="article ii", heading="Payment"
    )
    added = _clause("added", "Article III Notices\nAdded.", label="article iii", heading="Notices")

    facts = diff_contracts(_contract(kept_before, removed), _contract(kept_after, added, sha="b"))

    assert {
        (item.kind, item.before_clause_id, item.after_clause_id) for item in facts.clause_changes
    } == {
        (ClauseChangeKind.REMOVED, "removed", None),
        (ClauseChangeKind.ADDED, None, "added"),
    }


def test_diff_contracts_records_reordered_clauses_as_moved() -> None:
    first_before = _clause(
        "before-first", "Article I Parties\nStable.", label="article i", heading="Parties"
    )
    second_before = _clause(
        "before-second", "Article II Payment\nStable.", label="article ii", heading="Payment"
    )
    first_after = first_before.model_copy(update={"id": "after-first"})
    second_after = second_before.model_copy(update={"id": "after-second"})

    facts = diff_contracts(
        _contract(first_before, second_before),
        _contract(second_after, first_after, sha="b"),
    )

    assert {item.kind for item in facts.clause_changes} == {ClauseChangeKind.MOVED}
    assert len(facts.clause_changes) == 2


def test_modification_is_not_hidden_when_clause_also_moves() -> None:
    payment_before = _clause("payment-before", _payment_text(30))
    general_before = _clause(
        "general-before",
        "Article III General\nStable.",
        label="article iii",
        heading="General",
    )
    payment_after = _clause("payment-after", _payment_text(45))
    general_after = general_before.model_copy(update={"id": "general-after"})

    facts = diff_contracts(
        _contract(payment_before, general_before),
        _contract(general_after, payment_after, sha="b"),
    )

    payment_change = next(
        item for item in facts.clause_changes if item.after_clause_id == "payment-after"
    )
    assert payment_change.kind is ClauseChangeKind.MODIFIED
    assert any(item.kind is ClauseChangeKind.MOVED for item in facts.clause_changes)


def test_unique_fingerprints_pair_duplicate_identities_without_order_choice() -> None:
    first = _clause("before-first", "Article II Payment Terms\nFirst.")
    second = _clause("before-second", "Article II Payment Terms\nSecond.")
    first_after = first.model_copy(update={"id": "after-first"})
    second_after = second.model_copy(update={"id": "after-second"})

    facts = diff_contracts(_contract(first, second), _contract(second_after, first_after, sha="b"))

    assert facts.unresolved_clause_ids == []
    assert {
        (item.before_clause_id, item.after_clause_id, item.kind) for item in facts.clause_changes
    } == {
        ("before-first", "after-first", ClauseChangeKind.MOVED),
        ("before-second", "after-second", ClauseChangeKind.MOVED),
    }


def test_entity_multisets_cover_all_protected_value_kinds() -> None:
    before_text = (
        "Article II Payment Terms\nParty A: Alpha Ltd.; on 2026-08-04 pay USD 100 "
        "within 30 days with a 5% fee."
    )
    after_text = (
        "Article II Payment Terms\nParty A: Beta Ltd.; on 2026-09-05 pay EUR 200 "
        "within 45 days with a 7% fee."
    )

    facts = diff_contracts(
        _contract(_clause("before", before_text)),
        _contract(_clause("after", after_text), sha="b"),
    )

    assert {
        (item.kind.value, item.before_value, item.after_value) for item in facts.entity_changes
    } == {
        ("party", "Alpha Ltd.", "Beta Ltd."),
        ("currency", "USD", "EUR"),
        ("money", "100", "200"),
        ("date", "2026-08-04", "2026-09-05"),
        ("duration", "30 day", "45 day"),
        ("percentage", "5", "7"),
    }
    clause_change = facts.clause_changes[0]
    assert clause_change.before_evidence and clause_change.after_evidence
    assert {item.clause_change_id for item in facts.entity_changes} == {clause_change.id}


def test_ambiguous_entity_values_are_separate_additions_and_removals() -> None:
    before = _clause("before", "Article II Payment Terms\nPay within 30 days or 60 days.")
    after = _clause("after", "Article II Payment Terms\nPay within 45 days or 90 days.")

    facts = diff_contracts(_contract(before), _contract(after, sha="b"))

    durations = [item for item in facts.entity_changes if item.kind.value == "duration"]
    assert len(durations) == 4
    assert all(item.before_value is None or item.after_value is None for item in durations)
    assert {item.before_value for item in durations if item.before_value is not None} == {
        "30 day",
        "60 day",
    }
    assert {item.after_value for item in durations if item.after_value is not None} == {
        "45 day",
        "90 day",
    }


def test_exact_entity_multiset_cancellation_leaves_one_conservative_pair() -> None:
    before = _clause("before", "Article II Payment Terms\nPeriods: 30 days, 30 days, and 60 days.")
    after = _clause("after", "Article II Payment Terms\nPeriods: 30 days, 45 days, and 60 days.")

    facts = diff_contracts(_contract(before), _contract(after, sha="b"))

    durations = [item for item in facts.entity_changes if item.kind.value == "duration"]
    assert [(item.before_value, item.after_value) for item in durations] == [("30 day", "45 day")]


def test_fact_models_reject_unknown_and_unsafe_coerced_inputs() -> None:
    with pytest.raises(ValidationError):
        ClauseChange.model_validate({"id": "fact-1", "kind": b"modified", "surprise": True})
    with pytest.raises(ValidationError):
        ContractChangeSet.model_validate({"baseline_sha256": 1, "candidate_sha256": "b" * 64})
    with pytest.raises(ValidationError):
        ContractChangeSet.model_validate(
            {
                "baseline_sha256": "a" * 64,
                "candidate_sha256": "b" * 64,
                "unresolved_clause_ids": {"unordered"},
            }
        )


def test_unknown_metadata_relevance_cannot_be_downgraded_to_non_business() -> None:
    baseline = _contract().model_copy(
        update={
            "features": [
                DocumentFeature(
                    id="before-feature",
                    kind=DocumentFeatureKind.METADATA,
                    fingerprint="1" * 64,
                    count=1,
                    details={
                        "metadata_key": "contract_value",
                        "business_relevance": "non_business",
                    },
                )
            ]
        }
    )
    candidate = _contract(sha="b")

    facts = diff_contracts(baseline, candidate)

    assert len(facts.feature_changes) == 1
    assert facts.feature_changes[0].business_relevance == "business"


def test_malformed_feature_details_and_machine_paths_do_not_enter_fact_ids() -> None:
    def feature(identifier: str, value: str, machine_path: str) -> DocumentFeature:
        return DocumentFeature(
            id=identifier,
            kind=DocumentFeatureKind.EXTERNAL_LINK,
            fingerprint=value,
            count=1,
            evidence=[EvidenceRef(block_id=f"{machine_path}:block", page_index=9)],
            details={
                "host_hash": machine_path,
                "part_name": machine_path,
                "uri_scheme": "https",
            },
        )

    first = diff_contracts(
        _contract().model_copy(update={"features": [feature("before-1", "1" * 64, "C:/temp/one")]}),
        _contract(sha="b").model_copy(
            update={"features": [feature("after-1", "2" * 64, "C:/temp/two")]}
        ),
    )
    second = diff_contracts(
        _contract().model_copy(
            update={"features": [feature("before-2", "1" * 64, "D:/machine/alpha")]}
        ),
        _contract(sha="b").model_copy(
            update={"features": [feature("after-2", "2" * 64, "D:/machine/beta")]}
        ),
    )

    assert [item.id for item in first.feature_changes] == [
        item.id for item in second.feature_changes
    ]


def test_region_text_and_image_fingerprints_are_diffed_together() -> None:
    baseline = _contract().model_copy(
        update={
            "protected_regions": [
                ProtectedRegion(
                    id="before-header",
                    kind=ProtectedRegionKind.HEADER,
                    text_fingerprint="1" * 64,
                    feature_fingerprints=["2" * 64],
                )
            ]
        }
    )
    candidate = _contract(sha="b").model_copy(
        update={
            "protected_regions": [
                ProtectedRegion(
                    id="after-header",
                    kind=ProtectedRegionKind.HEADER,
                    text_fingerprint="1" * 64,
                    feature_fingerprints=["3" * 64],
                )
            ]
        }
    )

    facts = diff_contracts(baseline, candidate)

    assert len(facts.region_changes) == 1
    change = facts.region_changes[0]
    assert change.kind is ProtectedRegionKind.HEADER
    assert change.before_fingerprint != change.after_fingerprint


def test_ambiguous_region_groups_are_not_arbitrarily_paired() -> None:
    before_regions = [
        ProtectedRegion(
            id=f"before-{index}",
            kind=ProtectedRegionKind.SIGNATURE,
            text_fingerprint=str(index) * 64,
        )
        for index in (1, 2)
    ]
    after_regions = [
        ProtectedRegion(
            id=f"after-{index}",
            kind=ProtectedRegionKind.SIGNATURE,
            text_fingerprint=str(index) * 64,
        )
        for index in (3, 4)
    ]

    facts = diff_contracts(
        _contract().model_copy(update={"protected_regions": before_regions}),
        _contract(sha="b").model_copy(update={"protected_regions": after_regions}),
    )

    assert len(facts.region_changes) == 4
    assert all(
        item.before_fingerprint is None or item.after_fingerprint is None
        for item in facts.region_changes
    )


@pytest.mark.parametrize(
    ("kind", "before_details", "after_details", "expected_relevance"),
    [
        (DocumentFeatureKind.COMMENT, {}, {}, "business"),
        (
            DocumentFeatureKind.TRACKED_REVISION,
            {"revision_type": "insertion"},
            {"revision_type": "insertion"},
            "business",
        ),
        (
            DocumentFeatureKind.HIDDEN_TEXT,
            {"hidden_kind": "vanish"},
            {"hidden_kind": "vanish"},
            "business",
        ),
        (
            DocumentFeatureKind.EXTERNAL_LINK,
            {"host_hash": "a" * 64, "uri_scheme": "https"},
            {"host_hash": "a" * 64, "uri_scheme": "https"},
            "business",
        ),
        (DocumentFeatureKind.EMBEDDED_IMAGE, {}, {}, "business"),
        (
            DocumentFeatureKind.METADATA,
            {"metadata_key": "creator", "business_relevance": "non_business"},
            {"metadata_key": "creator", "business_relevance": "non_business"},
            "non_business",
        ),
    ],
)
def test_feature_kinds_pair_only_within_stable_semantic_groups(
    kind: DocumentFeatureKind,
    before_details: dict[str, object],
    after_details: dict[str, object],
    expected_relevance: str,
) -> None:
    baseline = _contract().model_copy(
        update={"features": [_feature("before", kind, "1" * 64, details=before_details)]}
    )
    candidate = _contract(sha="b").model_copy(
        update={"features": [_feature("after", kind, "2" * 64, details=after_details)]}
    )

    facts = diff_contracts(baseline, candidate)

    assert len(facts.feature_changes) == 1
    change = facts.feature_changes[0]
    assert (change.before_fingerprint, change.after_fingerprint) == (
        "1" * 64,
        "2" * 64,
    )
    assert change.business_relevance == expected_relevance


def test_cross_format_transient_feature_details_cancel_exact_content() -> None:
    baseline = _contract(format="docx").model_copy(
        update={
            "features": [
                _feature(
                    "docx-image",
                    DocumentFeatureKind.EMBEDDED_IMAGE,
                    "a" * 64,
                    details={
                        "image_part": "word/media/image1.png",
                        "part_name": "word/document.xml",
                    },
                )
            ]
        }
    )
    candidate = _contract(sha="b", format="pdf").model_copy(
        update={
            "features": [
                _feature(
                    "pdf-image",
                    DocumentFeatureKind.EMBEDDED_IMAGE,
                    "a" * 64,
                    details={"extraction_confidence": "content", "page_index": 7},
                )
            ]
        }
    )

    assert diff_contracts(baseline, candidate).feature_changes == []


def test_feature_and_region_input_permutations_produce_identical_bytes() -> None:
    before_features = [
        _feature("image-old", DocumentFeatureKind.EMBEDDED_IMAGE, "1" * 64),
        _feature(
            "metadata-old",
            DocumentFeatureKind.METADATA,
            "2" * 64,
            details={"metadata_key": "creator", "business_relevance": "non_business"},
        ),
    ]
    after_features = [
        _feature("image-new", DocumentFeatureKind.EMBEDDED_IMAGE, "3" * 64),
        _feature(
            "metadata-new",
            DocumentFeatureKind.METADATA,
            "4" * 64,
            details={"metadata_key": "creator", "business_relevance": "non_business"},
        ),
    ]
    before_regions = [
        ProtectedRegion(
            id="header-old",
            kind=ProtectedRegionKind.HEADER,
            text_fingerprint="5" * 64,
        ),
        ProtectedRegion(
            id="footer-old",
            kind=ProtectedRegionKind.FOOTER,
            text_fingerprint="6" * 64,
        ),
    ]
    after_regions = [
        ProtectedRegion(
            id="header-new",
            kind=ProtectedRegionKind.HEADER,
            text_fingerprint="7" * 64,
        ),
        ProtectedRegion(
            id="footer-new",
            kind=ProtectedRegionKind.FOOTER,
            text_fingerprint="8" * 64,
        ),
    ]

    first = diff_contracts(
        _contract().model_copy(
            update={"features": before_features, "protected_regions": before_regions}
        ),
        _contract(sha="b").model_copy(
            update={"features": after_features, "protected_regions": after_regions}
        ),
    )
    permuted = diff_contracts(
        _contract().model_copy(
            update={
                "features": list(reversed(before_features)),
                "protected_regions": list(reversed(before_regions)),
            }
        ),
        _contract(sha="b").model_copy(
            update={
                "features": list(reversed(after_features)),
                "protected_regions": list(reversed(after_regions)),
            }
        ),
    )

    assert first.model_dump_json() == permuted.model_dump_json()


def test_duplicate_feature_relevance_is_fail_closed_and_order_independent() -> None:
    non_business = _feature(
        "non-business",
        DocumentFeatureKind.METADATA,
        "a" * 64,
        details={"metadata_key": "creator", "business_relevance": "non_business"},
    )
    business = _feature(
        "business",
        DocumentFeatureKind.METADATA,
        "a" * 64,
        details={"metadata_key": "creator"},
    )
    candidate = _contract(sha="b").model_copy(update={"features": [non_business]})

    first = diff_contracts(
        _contract().model_copy(update={"features": [non_business, business]}), candidate
    )
    permuted = diff_contracts(
        _contract().model_copy(update={"features": [business, non_business]}), candidate
    )

    assert first.model_dump_json() == permuted.model_dump_json()
    assert [item.business_relevance for item in first.feature_changes] == ["business"]


def test_fact_ids_are_stable_across_docx_pdf_segmentation_and_repeats() -> None:
    docx_before = _clause("docx-before", _payment_text(30), block_id="docx:0:paragraph")
    docx_after = _clause("docx-after", _payment_text(45), block_id="docx:1:paragraph")
    pdf_before = _clause("pdf-before", _payment_text(30), block_id="pdf:3:17").model_copy(
        update={"evidence": [EvidenceRef(block_id="pdf:3:17", page_index=3)]}
    )
    pdf_after = _clause("pdf-after", _payment_text(45), block_id="pdf:9:4").model_copy(
        update={"evidence": [EvidenceRef(block_id="pdf:9:4", page_index=9)]}
    )

    docx_facts = diff_contracts(
        _contract(docx_before, format="docx"),
        _contract(docx_after, sha="b", format="docx"),
    )
    pdf_facts = diff_contracts(
        _contract(pdf_before, format="pdf"),
        _contract(pdf_after, sha="b", format="pdf"),
    )

    assert [item.id for item in docx_facts.clause_changes] == [
        item.id for item in pdf_facts.clause_changes
    ]
    assert [item.id for item in docx_facts.entity_changes] == [
        item.id for item in pdf_facts.entity_changes
    ]
    assert (
        docx_facts.model_dump_json()
        == diff_contracts(
            _contract(docx_before, format="docx"),
            _contract(docx_after, sha="b", format="docx"),
        ).model_dump_json()
    )
