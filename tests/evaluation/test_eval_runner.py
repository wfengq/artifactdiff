import time
from pathlib import Path

from evaluation.models import CaseResult, Expectation, Format
from evaluation.mutations import OPERATORS
from evaluation.runner import CaseJob, RunResult, run_cases
from evaluation.sources import load_synthetic


def _sleepy(job: CaseJob) -> CaseResult:
    if job.key.operator == "money_change":
        time.sleep(5)
    return CaseResult(
        key=job.key,
        expectation=job.expectation,
        text_verdict="pass" if job.expectation is Expectation.ACCEPT else "fail",
        raw_outcome="review",
        nonpass_rule_ids=(),
        edited_clause_chars=job.prepared.edited_clause_chars,
        baseline_clause_count=job.prepared.baseline_clause_count,
        duration_s=0.0,
        error=None,
    )


def _without_durations(run: RunResult) -> list[dict[str, object]]:
    rows = [result.to_json() for result in run.results]
    for row in rows:
        row.pop("duration_s")
    return rows


def test_runner_synthetic_one_seed_end_to_end(tmp_path: Path) -> None:
    run = run_cases(
        load_synthetic()[:1],
        [Format.DOCX],
        seed=0,
        workers=2,
        case_timeout=60,
        workdir=tmp_path,
    )
    assert run.draft_failures == []
    assert [r.key for r in run.results] == sorted(r.key for r in run.results)
    assert {r.key.operator for r in run.results} == {spec.name for spec in OPERATORS}
    assert all(r.error is None for r in run.results)
    authorized = [r for r in run.results if r.key.operator == "authorized"]
    assert len(authorized) == 1 and authorized[0].accepted
    assert not [r.key.operator for r in run.results if r.false_pass]


def test_runner_records_timeout_and_continues(tmp_path: Path) -> None:
    run = run_cases(
        load_synthetic()[:1],
        [Format.DOCX],
        seed=0,
        workers=2,
        case_timeout=1,
        workdir=tmp_path,
        case_fn=_sleepy,
    )
    by_operator = {r.key.operator: r for r in run.results}
    assert by_operator["money_change"].error is not None
    assert by_operator["money_change"].error.startswith("timeout")
    assert by_operator["money_change"].text_verdict is None
    assert len(by_operator) == len(OPERATORS)
    assert by_operator["authorized"].error is None


def test_runner_results_are_deterministic_except_duration(tmp_path: Path) -> None:
    seeds = load_synthetic()[2:3]
    first = run_cases(seeds, [Format.PDF], seed=0, workers=2, case_timeout=60, workdir=tmp_path / "a")
    second = run_cases(seeds, [Format.PDF], seed=0, workers=2, case_timeout=60, workdir=tmp_path / "b")
    assert _without_durations(first) == _without_durations(second)
    assert first.not_applicable == second.not_applicable


def test_runner_records_draft_failures_without_cases(tmp_path: Path) -> None:
    from evaluation.models import SourceContract

    contract = SourceContract("cuad", "empty", "en", ("Joint Filing Agreement",), None)
    run = run_cases([contract], [Format.DOCX], seed=0, workers=1, case_timeout=60, workdir=tmp_path)
    assert run.results == []
    assert [f.reason for f in run.draft_failures] == ["no-unique-target"]
