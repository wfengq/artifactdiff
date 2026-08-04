import json
from pathlib import Path
from typing import Any, cast

import pytest

from artifactdiff.contract import inspect_contract, load_contract
from artifactdiff.contract.models import ContractClause, ContractDocument, EntityKind
from artifactdiff.contract.selectors import (
    ClauseSelector,
    SelectorResolutionStatus,
    resolve_baseline,
    resolve_candidate,
)
from artifactdiff.errors import InputValidationError
from tests.factories import (
    ContractLanguage,
    make_contract_docx,
    make_contract_pdf,
)

FACTORIES = {
    "docx": make_contract_docx,
    "pdf": make_contract_pdf,
}
LANGUAGE_KINDS: dict[ContractLanguage, str] = {
    "zh": "zh",
    "en": "en",
    "zh-en": "zh-en",
}
PAYMENT_ENTITY_KINDS = {
    EntityKind.PARTY,
    EntityKind.MONEY,
    EntityKind.DATE,
    EntityKind.DURATION,
    EntityKind.PERCENTAGE,
}


def _payment_clause(contract: ContractDocument) -> ContractClause:
    matches = [
        clause
        for clause in contract.clauses
        if PAYMENT_ENTITY_KINDS <= {entity.kind for entity in clause.entities}
    ]
    assert len(matches) == 1
    return matches[0]


def _selector_for_payment_clause(contract: ContractDocument) -> ClauseSelector:
    payment = _payment_clause(contract)
    anchor = payment.text.splitlines()[-1]
    return ClauseSelector(
        clause_label=payment.label.normalized,
        heading=payment.heading,
        ancestor_path=payment.ancestor_path,
        anchor=anchor,
        baseline_fingerprint=payment.fingerprint,
    )


@pytest.mark.parametrize("language", ["zh", "en", "zh-en"])
@pytest.mark.parametrize("format_name", ["docx", "pdf"])
def test_contract_factories_are_byte_stable(
    tmp_path: Path, format_name: str, language: ContractLanguage
) -> None:
    factory = FACTORIES[format_name]
    first = factory(tmp_path / f"first.{format_name}", language=language)
    second = factory(tmp_path / f"second.{format_name}", language=language)

    assert second.read_bytes() == first.read_bytes()


@pytest.mark.parametrize("language", ["zh", "en", "zh-en"])
@pytest.mark.parametrize("format_name", ["docx", "pdf"])
def test_inspect_contract_is_stable_for_all_language_and_format_fixtures(
    tmp_path: Path, format_name: str, language: ContractLanguage
) -> None:
    source = FACTORIES[format_name](
        tmp_path / f"contract.{format_name}", language=language
    )

    first = inspect_contract(source)
    second = inspect_contract(source)

    assert second == first
    assert cast(dict[str, Any], first["language"])["kind"] == LANGUAGE_KINDS[language]
    assert len(cast(list[object], first["clauses"])) == 4
    assert PAYMENT_ENTITY_KINDS <= {
        EntityKind(item["kind"])
        for item in cast(list[dict[str, Any]], first["entities"])
    }
    region_kinds = {
        item["kind"]
        for item in cast(list[dict[str, Any]], first["protected_regions"])
    }
    assert {"signature", "seal", "attachment"} <= region_kinds
    if format_name == "docx":
        assert {"header", "footer"} <= region_kinds
    else:
        image_features = [
            item
            for item in cast(list[dict[str, Any]], first["features"])
            if item["kind"] == "embedded_image"
        ]
        assert sum(cast(int, item["count"]) for item in image_features) == 2


def test_inspect_contract_returns_bounded_portable_text_minimizing_ir(
    tmp_path: Path,
) -> None:
    source = make_contract_docx(tmp_path / "contract.docx", language="zh")

    full = inspect_contract(source)
    bounded = inspect_contract(source, max_clauses=2)

    assert len(cast(list[object], bounded["clauses"])) == 2
    assert bounded["truncated_clauses"] is True
    assert {
        key: value for key, value in bounded.items() if key not in {"clauses", "truncated_clauses"}
    } == {
        key: value for key, value in full.items() if key not in {"clauses", "truncated_clauses"}
    }
    serialized = json.dumps(bounded, ensure_ascii=False, sort_keys=True)
    assert "artifactdiff-contract-" not in serialized
    assert "Private Contract Author" not in serialized


@pytest.mark.parametrize("max_clauses", [-1, 1001])
def test_inspect_contract_validates_clause_bound_before_source_work(
    tmp_path: Path, max_clauses: int
) -> None:
    missing = tmp_path / "missing.docx"

    with pytest.raises(
        InputValidationError, match="max_clauses must be between 0 and 1000"
    ):
        inspect_contract(missing, max_clauses=max_clauses)


def test_inspect_contract_accepts_zero_clause_limit(tmp_path: Path) -> None:
    source = make_contract_docx(tmp_path / "contract.docx", language="en")

    result = inspect_contract(source, max_clauses=0)

    assert result["clauses"] == []
    assert result["truncated_clauses"] is True


def test_inspect_contract_honors_absolute_path_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_contract_docx(tmp_path / "contract.docx", language="en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(InputValidationError, match="Path must be absolute"):
        inspect_contract(Path("contract.docx"), require_absolute=True)


@pytest.mark.parametrize("language", ["zh", "en", "zh-en"])
def test_docx_and_pdf_contracts_resolve_the_derived_payment_selector(
    tmp_path: Path, language: ContractLanguage
) -> None:
    _, docx = load_contract(
        make_contract_docx(tmp_path / "contract.docx", language=language),
        render=False,
        force=False,
        workdir=tmp_path / "docx-work",
    )
    _, pdf = load_contract(
        make_contract_pdf(tmp_path / "contract.pdf", language=language),
        render=False,
        force=False,
        workdir=tmp_path / "pdf-work",
    )
    selector = _selector_for_payment_clause(docx)
    payment = _payment_clause(docx)

    baseline = resolve_baseline(docx, selector)
    candidate = resolve_candidate(pdf, selector)

    assert baseline.status is SelectorResolutionStatus.UNIQUE
    assert baseline.matches[0].clause_id == payment.id
    assert candidate.status is SelectorResolutionStatus.HIGH_CONFIDENCE


def test_derived_payment_selector_fails_closed_for_ambiguous_candidate(
    tmp_path: Path,
) -> None:
    _, baseline = load_contract(
        make_contract_docx(tmp_path / "contract.docx", language="en"),
        render=False,
        force=False,
        workdir=tmp_path / "docx-work",
    )
    _, candidate = load_contract(
        make_contract_pdf(tmp_path / "contract.pdf", language="en"),
        render=False,
        force=False,
        workdir=tmp_path / "pdf-work",
    )
    payment = _payment_clause(candidate)
    duplicate = payment.model_copy(update={"id": f"{payment.id}-duplicate"})
    ambiguous = candidate.model_copy(update={"clauses": [*candidate.clauses, duplicate]})

    resolution = resolve_candidate(ambiguous, _selector_for_payment_clause(baseline))

    assert resolution.status is SelectorResolutionStatus.AMBIGUOUS
