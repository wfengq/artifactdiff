from base64 import b64decode
from pathlib import Path

from bs4 import BeautifulSoup
import pytest

from artifactdiff.models import ComparisonResult, SourceDescriptor
from artifactdiff.reporting.html import write_html
from tests.factories import sample_changed_result_with_images


def _document(path: Path) -> tuple[str, BeautifulSoup]:
    html = path.read_text(encoding="utf-8")
    return html, BeautifulSoup(html, "html.parser")


def _unchanged_result() -> ComparisonResult:
    before = SourceDescriptor(path="before.pdf", sha256="a" * 64, format="pdf", size_bytes=10)
    after = SourceDescriptor(path="after.pdf", sha256="a" * 64, format="pdf", size_bytes=10)
    return ComparisonResult.unchanged(before, after)


def test_html_report_is_self_contained(tmp_path: Path) -> None:
    result, assets = sample_changed_result_with_images(tmp_path)
    report = write_html(result, assets, tmp_path / "report.html")
    html, document = _document(report)

    assert "ArtifactDiff" in html
    assert "https://" not in html
    assert "http://" not in html
    assert "file:" not in html
    assert document.find("link") is None
    assert all(not script.get("src") for script in document.find_all("script"))
    assert document.select_one('[data-mode="heatmap"]') is not None
    assert document.select_one('[data-filter="modified"]') is not None
    images = document.find_all("img")
    assert len(images) == 3
    for image in images:
        source = image["src"]
        assert source.startswith("data:image/png;base64,")
        assert b64decode(source.partition(",")[2], validate=True).startswith(b"\x89PNG\r\n\x1a\n")


def test_html_report_escapes_untrusted_paths_text_and_warnings(tmp_path: Path) -> None:
    result, assets = sample_changed_result_with_images(tmp_path)
    path_value = '<img id="path-injected" src=x onerror=alert(1)>before.pdf'
    warning_value = '</script><script id="warning-injected">alert(2)</script>'
    text_value = '</del><script id="text-injected">alert(3)</script>'
    change = result.changes[0].model_copy(
        update={"before": result.changes[0].before.model_copy(update={"text": text_value})}
    )
    result = result.model_copy(
        update={
            "status": "partial",
            "before": result.before.model_copy(update={"path": path_value}),
            "warnings": [warning_value],
            "changes": [change],
        }
    )

    report = write_html(result, assets, tmp_path / "report.html")
    html, document = _document(report)
    text = document.get_text(" ", strip=True)

    assert document.select_one('[role="alert"]') is not None
    assert len(document.find_all("script")) == 1
    assert document.find(id="path-injected") is None
    assert document.find(id="warning-injected") is None
    assert document.find(id="text-injected") is None
    assert path_value in text
    assert warning_value in text
    assert text_value in text
    assert "&lt;script" in html


def test_unchanged_report_shows_source_schema_status_and_empty_states(tmp_path: Path) -> None:
    report = write_html(_unchanged_result(), {}, tmp_path / "report.html")
    html, document = _document(report)

    assert document.body["data-status"] == "unchanged"
    assert "Schema 1.0" in document.get_text(" ", strip=True)
    assert "a" * 64 in html
    assert document.select_one(".source-before") is not None
    assert document.select_one(".source-after") is not None
    assert document.select_one(".visual-empty") is not None
    assert document.select_one(".semantic-empty") is not None
    assert document.find("img") is None


def test_partial_report_without_warning_details_shows_generic_warning(tmp_path: Path) -> None:
    result = _unchanged_result().model_copy(update={"status": "partial"})

    report = write_html(result, {}, tmp_path / "report.html")
    _, document = _document(report)
    warning = document.select_one('[role="alert"]')

    assert warning is not None
    assert "some results may be unavailable" in warning.get_text(" ", strip=True).casefold()


def test_html_report_bytes_are_stable(tmp_path: Path) -> None:
    result, assets = sample_changed_result_with_images(tmp_path)
    first = write_html(result, assets, tmp_path / "first" / "report.html")
    second = write_html(
        result, dict(reversed(list(assets.items()))), tmp_path / "second" / "report.html"
    )

    assert first.read_bytes() == second.read_bytes()


def test_html_report_rejects_missing_visual_assets(tmp_path: Path) -> None:
    result, _ = sample_changed_result_with_images(tmp_path)

    with pytest.raises(ValueError, match="page-1"):
        write_html(result, {}, tmp_path / "report.html")


def test_html_report_removes_temporary_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, assets = sample_changed_result_with_images(tmp_path)
    report = tmp_path / "report.html"

    def fail_replace(self: Path, target: Path) -> Path:
        raise OSError("replace failed")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        write_html(result, assets, report)

    assert not report.exists()
    assert not report.with_suffix(".html.tmp").exists()
