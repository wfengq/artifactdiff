from pathlib import Path
from unittest.mock import Mock

import pytest
from PIL import Image

from artifactdiff.errors import InputValidationError, RenderUnavailableError
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, PageSnapshot
from artifactdiff.service import CompareOptions, compare_documents, inspect_document
from artifactdiff.visual_service import compare_visual_pages
from tests.factories import make_docx, make_pdf


def _snapshot(
    path: Path,
    workdir: Path,
    *,
    texts: list[str],
    render: bool,
    warnings: list[str] | None = None,
    colors: list[str] | None = None,
) -> DocumentSnapshot:
    pages: list[PageSnapshot] = []
    blocks: list[ContentBlock] = []
    for index, page_text in enumerate(texts):
        block = ContentBlock(
            id=f"{path.stem}-{index}",
            ordinal=index,
            page_index=index,
            content_type=ContentType.PDF_TEXT,
            text=page_text,
            normalized_text=page_text.casefold(),
        )
        render_path = None
        if render:
            image_path = workdir / "pages" / f"{index}.png"
            image_path.parent.mkdir(parents=True, exist_ok=True)
            color = colors[index] if colors is not None else "white"
            Image.new("RGB", (10 * (index + 1), 10), color).save(image_path)
            render_path = str(image_path)
        pages.append(
            PageSnapshot(
                index=index,
                width=100,
                height=100,
                text=page_text,
                normalized_text=page_text.casefold(),
                blocks=[block],
                render_path=render_path,
            )
        )
        blocks.append(block)
    return DocumentSnapshot.from_path(path, pages=pages, blocks=blocks, warnings=warnings)


class FakeAdapter:
    def __init__(
        self,
        *,
        texts: dict[str, list[str]],
        warnings: dict[str, list[str]] | None = None,
        colors: dict[str, list[str]] | None = None,
    ) -> None:
        self.texts = texts
        self.warnings = warnings or {}
        self.colors = colors or {}
        self.calls: list[tuple[Path, bool, Path, bool]] = []

    def load(
        self, path: Path, *, render: bool, workdir: Path, force: bool = False
    ) -> DocumentSnapshot:
        self.calls.append((path, render, workdir, force))
        return _snapshot(
            path,
            workdir,
            texts=self.texts[path.name],
            render=render,
            warnings=self.warnings.get(path.name),
            colors=self.colors.get(path.name),
        )


def _different_pdf_paths(tmp_path: Path) -> tuple[Path, Path]:
    before = tmp_path / "before.pdf"
    after = tmp_path / "after.pdf"
    before.write_bytes(b"before")
    after.write_bytes(b"after")
    return before, after


def test_changed_visual_run_passes_options_and_cleans_workdirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(
        texts={"before.pdf": ["Revenue 100"], "after.pdf": ["Revenue 101"]},
        colors={"before.pdf": ["white"], "after.pdf": ["black"]},
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)

    run = compare_documents(
        before,
        after,
        tmp_path / "report",
        options=CompareOptions(force=True, pixel_threshold=7, tile_size=8),
    )

    assert [(call[1], call[3]) for call in adapter.calls] == [(True, True), (True, True)]
    assert [call[2].name for call in adapter.calls] == ["before", "after"]
    assert adapter.calls[0][2] != adapter.calls[1][2]
    assert all(not call[2].exists() for call in adapter.calls)
    assert run.result.status == "changed"
    assert run.result.summary.model_dump() == {
        "added": 0,
        "removed": 0,
        "modified": 1,
        "moved": 0,
        "total_changes": 1,
        "visual_change_ratio": 1.0,
    }
    assert [(change.before_page, change.after_page) for change in run.result.visual_changes] == [
        (1, 1)
    ]
    assert set(run.visual_assets) == {run.result.visual_changes[0].id}
    for assets in run.visual_assets.values():
        assert all(
            path.is_file()
            for path in (assets.before_image, assets.after_image, assets.heatmap_image)
        )
    assert "artifactdiff-" not in run.json_path.read_text(encoding="utf-8")


def test_visual_false_skips_rendering_and_visual_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(texts={"before.pdf": ["Revenue 100"], "after.pdf": ["Revenue 101"]})
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)
    monkeypatch.setattr(
        "artifactdiff.visual_service.compare_images",
        Mock(side_effect=AssertionError("visual diff called")),
    )

    run = compare_documents(
        before, after, tmp_path / "report", options=CompareOptions(visual=False)
    )

    assert [call[1] for call in adapter.calls] == [False, False]
    assert run.result.status == "changed"
    assert run.result.visual_changes == []
    assert run.visual_assets == {}


def test_visual_page_service_preserves_unpaired_direction_when_requested(
    tmp_path: Path,
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    left = _snapshot(
        before,
        tmp_path / "before",
        texts=["Cover", "Deleted appendix"],
        render=True,
        colors=["white", "white"],
    )
    right = _snapshot(
        after,
        tmp_path / "after",
        texts=["Cover"],
        render=True,
        colors=["white"],
    )

    visual = compare_visual_pages(
        left,
        right,
        tmp_path / "output",
        pixel_threshold=16,
        tile_size=32,
        include_unpaired=True,
    )

    assert visual.available is True
    assert [
        (change.before_page, change.after_page, change.changed_pixel_ratio)
        for change in visual.visual_changes
    ] == [(2, None, 1.0)]
    assert visual.changed_pixel_ratio == 0.0
    assert not (tmp_path / "output" / "work").exists()


@pytest.mark.parametrize(
    ("after_color", "expected_status", "expected_ratio"),
    [("black", "changed", 1.0), ("white", "unchanged", 0.0)],
)
def test_visual_difference_controls_status_when_semantics_are_equal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after_color: str,
    expected_status: str,
    expected_ratio: float,
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(
        texts={"before.pdf": ["Same"], "after.pdf": ["Same"]},
        colors={"before.pdf": ["white"], "after.pdf": [after_color]},
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)

    run = compare_documents(before, after, tmp_path / "report", options=CompareOptions())

    assert run.result.status == expected_status
    assert run.result.summary.total_changes == 0
    assert run.result.summary.visual_change_ratio == expected_ratio


def test_single_sided_pages_are_skipped_and_paired_visuals_are_compared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(
        texts={
            "before.pdf": ["Cover", "Revenue 100", "Appendix"],
            "after.pdf": ["Cover", "Revenue 101"],
        },
        colors={
            "before.pdf": ["white", "white", "white"],
            "after.pdf": ["black", "gray"],
        },
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)

    run = compare_documents(before, after, tmp_path / "report", options=CompareOptions())

    assert [(change.before_page, change.after_page) for change in run.result.visual_changes] == [
        (1, 1),
        (2, 2),
    ]
    assert run.result.summary.visual_change_ratio == 1.0
    assert all(change.before_page != 3 for change in run.result.visual_changes)


def test_visual_failure_returns_partial_semantic_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(
        texts={"before.pdf": ["Revenue 100"], "after.pdf": ["Revenue 101"]},
        colors={"before.pdf": ["white"], "after.pdf": ["black"]},
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)
    monkeypatch.setattr(
        "artifactdiff.visual_service.compare_images",
        Mock(side_effect=RenderUnavailableError("renderer stopped")),
    )

    run = compare_documents(before, after, tmp_path / "report", options=CompareOptions())

    assert run.result.status == "partial"
    assert run.result.summary.modified == 1
    assert run.result.summary.total_changes == 1
    assert run.result.visual_changes == []
    assert run.result.warnings == ["Visual comparison unavailable: renderer stopped"]


def test_duplicate_snapshot_render_warnings_are_deduplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    warning = "DOCX visual rendering unavailable: LibreOffice was not found"
    adapter = FakeAdapter(
        texts={"before.pdf": ["Same"], "after.pdf": ["Same"]},
        warnings={"before.pdf": [warning], "after.pdf": [warning]},
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)

    run = compare_documents(before, after, tmp_path / "report", options=CompareOptions())

    assert run.result.status == "partial"
    assert run.result.warnings == [warning]


def test_compare_rejects_mismatched_formats(tmp_path: Path) -> None:
    pdf = make_pdf(
        tmp_path / "a.pdf",
        [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]],
    )
    docx = make_docx(tmp_path / "b.docx", heading="B", paragraphs=[], rows=[["B"]])

    with pytest.raises(InputValidationError, match="same supported format"):
        compare_documents(pdf, docx, tmp_path / "out", options=CompareOptions())


def test_inspect_document_bounds_blocks(tmp_path: Path) -> None:
    source = make_docx(
        tmp_path / "many.docx",
        heading="Heading",
        paragraphs=[str(index) for index in range(150)],
        rows=[["A"]],
    )

    inspection = inspect_document(source, max_blocks=10)

    assert len(inspection["blocks"]) == 10
    assert inspection["truncated"] is True
    assert inspection["page_count"] is None
    assert inspection["format"] == "docx"


def test_inspect_document_validates_absolute_path_and_block_limit(tmp_path: Path) -> None:
    source = make_docx(tmp_path / "sample.docx", heading="Heading", paragraphs=[], rows=[["A"]])
    with pytest.raises(InputValidationError, match="must be absolute"):
        inspect_document(Path(source.name), require_absolute=True)
    with pytest.raises(InputValidationError, match="max_blocks"):
        inspect_document(source, max_blocks=-1)
