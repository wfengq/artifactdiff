import pytest
from pydantic import ValidationError

from artifactdiff.contract.models import (
    ClauseLabel,
    ContractClause,
    ContractDocument,
    EntityKind,
    EvidenceRef,
    LanguageKind,
    LanguageProfile,
    ProtectedEntity,
)
from artifactdiff.models import Rect, SourceDescriptor


@pytest.fixture
def contract_document_data() -> dict[str, object]:
    source = SourceDescriptor(
        path="contract.docx", sha256="a" * 64, format="docx", size_bytes=123
    )
    evidence = EvidenceRef(
        block_id="block-1",
        page_index=0,
        bbox=Rect(x0=1, y0=2, x1=3, y1=4),
        rendered_page_index=0,
        rendered_bbox=Rect(x0=5, y0=6, x1=7, y1=8),
    )
    entity = ProtectedEntity(
        id="entity-1",
        kind=EntityKind.MONEY,
        text="RMB 10,000",
        normalized_value="10000",
        clause_id="clause-1",
        evidence=[evidence],
    )
    clause = ContractClause(
        id="clause-1",
        label=ClauseLabel(printed="Section 1", normalized="section 1", scheme="section"),
        heading="Payment",
        ancestor_path=("Agreement",),
        text="Pay RMB 10,000",
        normalized_text="pay rmb 10,000",
        fingerprint="fingerprint-1",
        evidence=[evidence],
        entities=[entity],
    )
    return ContractDocument(
        source=source,
        language=LanguageProfile(kind=LanguageKind.ENGLISH, latin_letters=10),
        clauses=[clause],
        tables=[evidence],
        entities=[entity],
    ).model_dump(mode="json")


def test_contract_document_rejects_unknown_fields(contract_document_data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ContractDocument.model_validate({**contract_document_data, "surprise": True})


def test_contract_document_json_round_trip_preserves_nested_evidence(
    contract_document_data: dict[str, object],
) -> None:
    document = ContractDocument.model_validate(contract_document_data)

    restored = ContractDocument.model_validate_json(document.model_dump_json())

    assert restored == document
    assert restored.clauses[0].entities[0].evidence[0].rendered_bbox == Rect(
        x0=5, y0=6, x1=7, y1=8
    )


def test_contract_models_default_collections_are_independent() -> None:
    source = SourceDescriptor(path="contract.pdf", sha256="b" * 64, format="pdf", size_bytes=1)
    language = LanguageProfile(kind=LanguageKind.OTHER)
    first = ContractDocument(source=source, language=language)
    second = ContractDocument(source=source, language=language)

    first.warnings.append("warning")

    assert second.warnings == []
