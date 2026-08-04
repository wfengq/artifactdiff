from pathlib import Path

import pytest
from PIL import Image

from artifactdiff.models import VisualPageChange
from artifactdiff.service import CompareOptions, compare_documents
from artifactdiff.visual import VisualAssets
from tests.integration.test_service_orchestration import FakeAdapter, _different_pdf_paths


def test_visuals_run_in_page_index_order_and_ratio_is_area_weighted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(
        texts={
            "before.pdf": ["First page", "Second page"],
            "after.pdf": ["First pages", "Second pages"],
        }
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)
    ratios = iter((0.5, 0.25))
    page_keys: list[str] = []

    def fake_compare(
        _before: Path,
        _after: Path,
        *,
        output_dir: Path,
        threshold: int,
        tile_size: int,
    ) -> tuple[VisualPageChange, VisualAssets]:
        assert threshold == 9
        assert tile_size == 16
        page_keys.append(output_dir.name)
        output_dir.mkdir(parents=True)
        size = (10, 10) if output_dir.name == "page-1-1" else (30, 10)
        paths = [output_dir / name for name in ("before.png", "after.png", "heatmap.png")]
        for path in paths:
            Image.new("RGB", size, "white").save(path)
        return (
            VisualPageChange(id="visual", changed_pixel_ratio=next(ratios)),
            VisualAssets(*paths),
        )

    monkeypatch.setattr("artifactdiff.service.compare_images", fake_compare)

    run = compare_documents(
        before,
        after,
        tmp_path / "report",
        options=CompareOptions(pixel_threshold=9, tile_size=16),
    )

    assert page_keys == ["page-1-1", "page-2-2"]
    assert run.result.summary.visual_change_ratio == pytest.approx(0.3125)
