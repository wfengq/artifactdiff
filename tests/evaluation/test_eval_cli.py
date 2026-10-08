import json
from pathlib import Path

import pytest

from evaluation.__main__ import main


def test_cli_rejects_non_empty_output(tmp_path: Path) -> None:
    (tmp_path / "x").write_text("x", encoding="utf-8")
    assert main(["run", "--source", "synthetic", "--output", str(tmp_path)]) == 2


def test_cli_cuad_without_data_points_to_fetch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        ["run", "--source", "cuad", "--data-dir", str(tmp_path), "--output", str(tmp_path / "o")]
    )
    assert code == 2
    assert "fetch-cuad" in capsys.readouterr().err


def test_cli_synthetic_run_writes_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out"
    code = main(
        ["run", "--source", "synthetic", "--formats", "docx", "--workers", "2", "--output", str(output)]
    )
    assert code == 0
    assert "False passes: 0/" in capsys.readouterr().out
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["metadata"]["source"] == "synthetic"
    assert summary["metadata"]["formats"] == ["docx"]
    assert (output / "report.md").is_file() and (output / "results.jsonl").is_file()


def test_cli_exits_nonzero_when_cases_errored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import evaluation.__main__ as cli
    from evaluation.models import CaseKey, CaseResult, Expectation
    from evaluation.runner import RunResult

    errored = CaseResult(
        key=CaseKey("synthetic", "en-services", "docx", "money_change"),
        expectation=Expectation.BLOCK,
        text_verdict=None,
        raw_outcome=None,
        nonpass_rule_ids=(),
        edited_clause_chars=100,
        baseline_clause_count=6,
        duration_s=1.0,
        error="timeout after 1s",
    )
    monkeypatch.setattr(
        cli,
        "run_cases",
        lambda *args, **kwargs: RunResult([errored], [], [], 0),
    )
    assert main(["run", "--source", "synthetic", "--output", str(tmp_path / "o")]) == 1
    assert "errors: 1" in capsys.readouterr().out
