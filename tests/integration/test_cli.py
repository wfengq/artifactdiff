import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from artifactdiff.cli import app
from artifactdiff.models import ComparisonResult, SourceDescriptor
from artifactdiff.service import CompareOptions, ComparisonRun
from tests.factories import make_docx, make_pdf

runner = CliRunner()


def _pdf_pair(tmp_path: Path) -> tuple[Path, Path]:
    before = make_pdf(
        tmp_path / "before.pdf",
        [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]],
    )
    after = make_pdf(
        tmp_path / "after.pdf",
        [[(200, 700, "Second"), (72, 720, "First"), (72, 680, "Third")]],
    )
    return before, after


def test_compare_writes_reports(tmp_path: Path) -> None:
    before, after = _pdf_pair(tmp_path)
    output = tmp_path / "report"

    response = runner.invoke(
        app,
        ["compare", str(before), str(after), "--output", str(output), "--no-visual"],
    )

    assert response.exit_code == 0, response.stderr
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()
    assert response.stdout.startswith("changed: ")


def test_fail_on_change_returns_one(tmp_path: Path) -> None:
    before, after = _pdf_pair(tmp_path)

    response = runner.invoke(
        app,
        [
            "compare",
            str(before),
            str(after),
            "--output",
            str(tmp_path / "out"),
            "--no-visual",
            "--fail-on-change",
        ],
    )

    assert response.exit_code == 1
    assert response.stdout.startswith("changed: ")


def test_fail_on_change_keeps_unchanged_at_zero(tmp_path: Path) -> None:
    source = make_pdf(
        tmp_path / "same.pdf",
        [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]],
    )

    response = runner.invoke(
        app,
        [
            "compare",
            str(source),
            str(source),
            "--output",
            str(tmp_path / "out"),
            "--fail-on-change",
        ],
    )

    assert response.exit_code == 0, response.stderr
    assert response.stdout.startswith("unchanged: ")


def test_compare_json_prints_only_machine_readable_result(tmp_path: Path) -> None:
    before, after = _pdf_pair(tmp_path)

    response = runner.invoke(
        app,
        [
            "compare",
            str(before),
            str(after),
            "--output",
            str(tmp_path / "out"),
            "--no-visual",
            "--json",
        ],
    )

    assert response.exit_code == 0, response.stderr
    payload = json.loads(response.stdout)
    assert payload["schema_version"] == "1.0"
    assert payload["status"] == "changed"
    assert response.stderr == ""


def test_compare_passes_all_processing_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = tmp_path / "before.pdf"
    after = tmp_path / "after.pdf"
    before.write_bytes(b"before")
    after.write_bytes(b"after")
    destination = tmp_path / "out"
    captured: dict[str, object] = {}
    descriptor = SourceDescriptor(
        path=str(before.resolve()), sha256="a" * 64, format="pdf", size_bytes=6
    )
    result = ComparisonResult(status="unchanged", before=descriptor, after=descriptor)

    def fake_compare_documents(
        before_path: Path,
        after_path: Path,
        output_dir: Path,
        *,
        options: object,
    ) -> ComparisonRun:
        captured.update(
            before=before_path,
            after=after_path,
            output=output_dir,
            options=options,
        )
        return ComparisonRun(
            result=result,
            json_path=destination / "report.json",
            html_path=destination / "report.html",
        )

    monkeypatch.setattr("artifactdiff.cli.compare_documents", fake_compare_documents)

    response = runner.invoke(
        app,
        [
            "compare",
            str(before),
            str(after),
            "--output",
            str(destination),
            "--no-visual",
            "--force",
            "--pixel-threshold",
            "41",
            "--tile-size",
            "64",
        ],
    )

    assert response.exit_code == 0, response.stderr
    options = captured["options"]
    assert options == CompareOptions(
        visual=False,
        force=True,
        pixel_threshold=41,
        tile_size=64,
    )
    assert captured == {
        "before": before,
        "after": after,
        "output": destination,
        "options": options,
    }


@pytest.mark.parametrize(
    ("option", "value"),
    [("--pixel-threshold", "256"), ("--tile-size", "7"), ("--tile-size", "257")],
)
def test_compare_rejects_out_of_range_visual_options(
    tmp_path: Path, option: str, value: str
) -> None:
    before, after = _pdf_pair(tmp_path)

    response = runner.invoke(
        app,
        ["compare", str(before), str(after), option, value],
    )

    assert response.exit_code == 2
    assert "Invalid value" in response.stderr


def test_public_error_returns_two_on_stderr_without_traceback(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pdf"

    response = runner.invoke(
        app,
        ["compare", str(missing), str(missing), "--output", str(tmp_path / "out")],
    )

    assert response.exit_code == 2
    assert response.stdout == ""
    assert "ArtifactDiff error:" in response.stderr
    assert "Traceback" not in response.stderr


def test_inspect_resolves_relative_path_and_bounds_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_docx(
        tmp_path / "many.docx",
        heading="Heading",
        paragraphs=[f"Paragraph {index}" for index in range(110)],
        rows=[["Name", "Value"], ["A", "1"]],
    )
    monkeypatch.chdir(tmp_path)

    response = runner.invoke(app, ["inspect", source.name])

    assert response.exit_code == 0, response.stderr
    payload = json.loads(response.stdout)
    assert payload["path"] == str(source.resolve())
    assert payload["format"] == "docx"
    assert payload["truncated"] is True
    assert len(payload["blocks"]) == 100
    assert response.stderr == ""


def test_inspect_public_error_returns_two_without_traceback(tmp_path: Path) -> None:
    response = runner.invoke(app, ["inspect", str(tmp_path / "missing.docx")])

    assert response.exit_code == 2
    assert response.stdout == ""
    assert "ArtifactDiff error:" in response.stderr
    assert "Traceback" not in response.stderr
