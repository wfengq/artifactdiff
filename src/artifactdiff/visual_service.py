"""Deterministic visual page comparison orchestration."""

from dataclasses import dataclass
from pathlib import Path
from shutil import copy2
from tempfile import TemporaryDirectory

from PIL import Image

from artifactdiff.alignment import AlignedPair, align_sequences
from artifactdiff.errors import RenderUnavailableError
from artifactdiff.models import DocumentSnapshot, PageSnapshot, VisualPageChange
from artifactdiff.visual import VisualAssets, compare_images


@dataclass(frozen=True, slots=True)
class VisualComparison:
    """Observed visual differences, copied artifacts, and availability state."""

    visual_changes: list[VisualPageChange]
    assets: dict[str, VisualAssets]
    warnings: list[str]
    changed_pixel_ratio: float
    available: bool


def compare_visual_pages(
    before: DocumentSnapshot,
    after: DocumentSnapshot,
    output_dir: Path,
    *,
    pixel_threshold: int,
    tile_size: int,
    include_unpaired: bool = False,
) -> VisualComparison:
    """Compare aligned rendered pages and copy changed-page artifacts."""
    warnings = [*before.warnings, *after.warnings]
    visual_changes: list[VisualPageChange] = []
    assets: dict[str, VisualAssets] = {}
    weighted_changed_pixels = 0.0
    compared_pixels = 0
    page_pairs = align_sequences(
        before.pages,
        after.pages,
        key=lambda page: page.normalized_text,
    )
    page_pairs.sort(key=_page_pair_order)
    available = bool(page_pairs)
    for pair in page_pairs:
        left = pair.before
        right = pair.after
        if left is None or right is None:
            if include_unpaired:
                key = _page_key(
                    left.index + 1 if left is not None else None,
                    right.index + 1 if right is not None else None,
                )
                visual_changes.append(
                    VisualPageChange(
                        id=key,
                        before_page=left.index + 1 if left is not None else None,
                        after_page=right.index + 1 if right is not None else None,
                        changed_pixel_ratio=1.0,
                    )
                )
            continue
        if left.render_path is None or right.render_path is None:
            warnings.append(
                "Visual comparison unavailable for "
                f"before page {left.index + 1} and after page {right.index + 1}: "
                "rendered page missing"
            )
            available = False
            continue
        key = _page_key(left.index + 1, right.index + 1)
        try:
            with TemporaryDirectory(prefix="artifactdiff-visual-") as temporary:
                visual, temporary_assets = compare_images(
                    Path(left.render_path),
                    Path(right.render_path),
                    output_dir=Path(temporary) / key,
                    threshold=pixel_threshold,
                    tile_size=tile_size,
                )
                area = _image_area(temporary_assets.before_image)
                compared_pixels += area
                weighted_changed_pixels += visual.changed_pixel_ratio * area
                if visual.changed_pixel_ratio == 0:
                    continue
                visual = visual.model_copy(
                    update={
                        "id": key,
                        "before_page": left.index + 1,
                        "after_page": right.index + 1,
                    }
                )
                visual_changes.append(visual)
                assets[key] = _copy_visual_assets(temporary_assets, output_dir / "visual" / key)
        except (RenderUnavailableError, OSError) as error:
            warnings.append(f"Visual comparison unavailable: {error}")
            available = False
            continue
    return VisualComparison(
        visual_changes=visual_changes,
        assets=assets,
        warnings=_deduplicate(warnings),
        changed_pixel_ratio=weighted_changed_pixels / compared_pixels if compared_pixels else 0.0,
        available=available,
    )


def _page_key(before_page: int | None, after_page: int | None) -> str:
    return f"page-{before_page if before_page is not None else 'none'}-{after_page if after_page is not None else 'none'}"


def _copy_visual_assets(assets: VisualAssets, destination: Path) -> VisualAssets:
    destination.mkdir(parents=True, exist_ok=True)
    copied = VisualAssets(
        before_image=destination / "before.png",
        after_image=destination / "after.png",
        heatmap_image=destination / "heatmap.png",
    )
    copy2(assets.before_image, copied.before_image)
    copy2(assets.after_image, copied.after_image)
    copy2(assets.heatmap_image, copied.heatmap_image)
    return copied


def _page_pair_order(pair: AlignedPair[PageSnapshot]) -> tuple[int, int]:
    if pair.before is not None:
        before_page = pair.before.index
        return (before_page, pair.after.index if pair.after is not None else before_page)
    assert pair.after is not None
    return (pair.after.index, pair.after.index)


def _image_area(path: Path) -> int:
    with Image.open(path) as image:
        return image.width * image.height


def _deduplicate(warnings: list[str]) -> list[str]:
    return list(dict.fromkeys(warnings))
