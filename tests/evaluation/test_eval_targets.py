from pathlib import Path

from artifactdiff import inspect_contract
from evaluation.models import AuthorizedEdit, DraftFailure, Format, SourceContract
from evaluation.render import render_docx
from evaluation.sources import load_synthetic
from evaluation.targets import PreparedContract, choose_edit, prepare


def _contract(*paragraphs: str) -> SourceContract:
    return SourceContract("cuad", "fixture", "en", tuple(paragraphs), None)


def _clauses(tmp_path: Path, contract: SourceContract) -> list[dict[str, object]]:
    path = render_docx(contract.paragraphs, tmp_path / "base.docx")
    clauses = inspect_contract(path, max_clauses=1000)["clauses"]
    assert isinstance(clauses, list)
    return clauses


def test_choose_edit_picks_unique_duration_with_preceding_anchor(tmp_path: Path) -> None:
    contract = _contract(
        "Article I Payment",
        "The Customer shall pay each undisputed invoice within 30 days of receipt.",
    )
    edit = choose_edit(contract, _clauses(tmp_path, contract))
    assert isinstance(edit, AuthorizedEdit)
    assert (edit.before, edit.after, edit.paragraph_index) == ("30 days", "45 days", 1)
    assert edit.anchor == "shall pay each undisputed invoice within"
    assert (edit.clause_label, edit.heading) == ("article i", "Payment")


def test_choose_edit_rejects_substring_of_larger_token(tmp_path: Path) -> None:
    contract = _contract(
        "Pay within 30 days of invoice.",
        "Deliver within 130 days of order and install within 130 days of delivery.",
    )
    assert choose_edit(contract, _clauses(tmp_path, contract)) == "no-unique-target"


def test_choose_edit_uses_following_words_when_few_precede(tmp_path: Path) -> None:
    contract = _contract("30 days notice is required before termination.")
    edit = choose_edit(contract, _clauses(tmp_path, contract))
    assert isinstance(edit, AuthorizedEdit)
    assert edit.anchor == "notice is required before termination."


def test_choose_edit_skips_candidate_whose_after_already_exists(tmp_path: Path) -> None:
    contract = _contract(
        "The Customer shall pay each invoice within 30 days of receipt.",
        "The Provider shall respond within 45 days and confirm within 45 days of notice.",
        "Late amounts accrue a fee of 5% per month under this agreement.",
    )
    edit = choose_edit(contract, _clauses(tmp_path, contract))
    assert isinstance(edit, AuthorizedEdit)
    assert (edit.before, edit.after) == ("5%", "6%")


def test_choose_edit_money_keeps_thousands_separators(tmp_path: Path) -> None:
    contract = _contract("The total price payable under this agreement is $48,000 in cash.")
    edit = choose_edit(contract, _clauses(tmp_path, contract))
    assert isinstance(edit, AuthorizedEdit)
    assert (edit.before, edit.after) == ("$48,000", "$49,000")


def test_prepare_short_contract_records_no_unique_target(tmp_path: Path) -> None:
    contract = _contract("Joint Filing Agreement", "The parties agree to file jointly.")
    result = prepare(contract, Format.DOCX, tmp_path)
    assert result == DraftFailure("cuad", "fixture", "docx", "no-unique-target")


def test_prepare_synthetic_seed_produces_sealed_policy(tmp_path: Path) -> None:
    for seed in load_synthetic():
        for fmt in Format:
            result = prepare(seed, fmt, tmp_path / seed.contract_id / fmt.value)
            assert isinstance(result, PreparedContract), result
            assert result.edit == seed.declared_edit
            assert result.sealed_policy_path.is_file()
            assert result.baseline_path.suffix == f".{fmt.value}"
            assert 0 < result.edited_clause_chars < 1000
            assert result.baseline_clause_count >= 6
