import json
from pathlib import Path

from evaluation.models import CaseKey, CaseResult, DraftFailure, Expectation
from evaluation.report import (
    RunMetadata,
    build_summary,
    clause_bucket,
    wilson_interval,
    write_report,
)
from evaluation.runner import RunResult
from evaluation.sources import CUAD_ATTRIBUTION


def _row(
    operator: str,
    verdict: str | None,
    *,
    expectation: Expectation = Expectation.BLOCK,
    rules: tuple[str, ...] = (),
    chars: int = 500,
    contract: str = "c1",
    fmt: str = "docx",
    error: str | None = None,
) -> CaseResult:
    return CaseResult(
        key=CaseKey("cuad", contract, fmt, operator),
        expectation=expectation,
        text_verdict=verdict,
        raw_outcome=verdict,
        nonpass_rule_ids=rules,
        edited_clause_chars=chars,
        baseline_clause_count=3,
        duration_s=1.0,
        error=error,
    )


def _metadata(source: str = "cuad") -> RunMetadata:
    return RunMetadata(
        source=source,
        cuad_sha256="abc" if source == "cuad" else None,
        artifactdiff_version="0.1.0",
        git_commit="deadbeef",
        seed=0,
        limit=2,
        formats=("docx",),
        options={"visual": False},
    )


RUN = RunResult(
    results=[
        _row("authorized", "pass", expectation=Expectation.ACCEPT, contract="c1"),
        _row(
            "authorized",
            "fail",
            expectation=Expectation.ACCEPT,
            rules=("contract-safe.expected.authorized", "contract-safe.unexplained-clause"),
            chars=2500,
            contract="c2",
        ),
        _row(
            "authorized",
            "fail",
            expectation=Expectation.ACCEPT,
            rules=("contract-safe.expected.authorized",),
            chars=6000,
            contract="c3",
        ),
        _row("money_change", "pass", contract="c1"),
        _row("money_change", "fail", contract="c2"),
        _row("modal_swap", "review", contract="c1"),
        _row("modal_swap", None, contract="c2", error="timeout after 1s"),
    ],
    draft_failures=[DraftFailure("cuad", "c4", "docx", "no-unique-target")],
    not_applicable=[(CaseKey("cuad", "c1", "docx", "party_change"), "no party")],
    pdf_replacements=0,
)


def test_wilson_interval_known_values() -> None:
    lo, hi = wilson_interval(0, 100)
    assert lo == 0.0 and abs(hi - 0.0370) < 1e-3
    lo, hi = wilson_interval(5, 100)
    assert abs(lo - 0.0215) < 1e-3 and abs(hi - 0.1118) < 1e-3
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_clause_bucket_boundaries() -> None:
    assert [clause_bucket(n) for n in (999, 1000, 1999, 2000, 4999, 5000)] == [
        "<1k",
        "1-2k",
        "1-2k",
        "2-5k",
        "2-5k",
        ">5k",
    ]


def test_summary_counts_false_passes_and_ranks_false_block_reasons() -> None:
    summary = build_summary(RUN, _metadata())
    false_pass = summary["false_pass"]
    assert false_pass["overall"]["count"] == 1
    assert false_pass["overall"]["total"] == 3
    assert false_pass["by_operator"]["money_change"]["count"] == 1
    assert false_pass["by_group"]["elsewhere"]["total"] == 3
    assert summary["blocked_split"]["modal_swap"] == {"fail": 0, "review": 1}
    acceptance = summary["acceptance"]
    assert (acceptance["accepted"], acceptance["total"]) == (1, 3)
    assert acceptance["false_block_reasons"] == [
        ["contract-safe.expected.authorized", 2],
        ["contract-safe.unexplained-clause", 1],
    ]
    assert acceptance["by_clause_bucket"]["2-5k"]["total"] == 1
    assert acceptance["by_clause_bucket"][">5k"]["accepted"] == 0
    assert summary["draftability"] == {
        "draftable": 3,
        "total": 4,
        "rate": 0.75,
        "reasons": [["no-unique-target", 1]],
    }
    assert summary["applicability"]["party_change"] == {"applicable": 0, "not_applicable": 1}
    assert summary["counts"]["errors"] == 1


def test_errors_are_neither_passes_nor_accepted() -> None:
    errored = RunResult(
        results=[
            _row("authorized", None, expectation=Expectation.ACCEPT, error="boom"),
            _row("money_change", None, error="boom"),
        ],
        draft_failures=[],
        not_applicable=[],
        pdf_replacements=0,
    )
    summary = build_summary(errored, _metadata())
    assert summary["false_pass"]["overall"] == {"count": 0, "total": 0, "rate": 0.0, "ci95": [0.0, 0.0]}
    assert (summary["acceptance"]["accepted"], summary["acceptance"]["total"]) == (0, 1)
    assert summary["acceptance"]["false_block_reasons"] == [["runner-error", 1]]


def test_report_contains_no_contract_text_and_cuad_attribution(tmp_path: Path) -> None:
    write_report(tmp_path, RUN, _metadata("cuad"))
    texts = {name: (tmp_path / name).read_text(encoding="utf-8") for name in ("results.jsonl", "summary.json", "report.md")}
    assert all("ZZSENTINEL" not in text for text in texts.values())
    assert CUAD_ATTRIBUTION in texts["report.md"]
    assert "False passes: 1/3 (33.33%, 95% CI" in texts["report.md"]
    assert "visual" in texts["report.md"].lower()
    rows = [json.loads(line) for line in texts["results.jsonl"].splitlines()]
    assert [row["key"]["operator"] for row in rows][:2] == ["authorized", "modal_swap"]
    assert json.loads(texts["summary.json"])["metadata"]["git_commit"] == "deadbeef"

    write_report(tmp_path / "s", RUN, _metadata("synthetic"))
    assert CUAD_ATTRIBUTION not in (tmp_path / "s" / "report.md").read_text(encoding="utf-8")
