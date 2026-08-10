"""Deterministic visual page comparison orchestration."""

from dataclasses import dataclass
from pathlib import Path
from shutil import copy2, rmtree
from tempfile import TemporaryDirectory, mkdtemp

from PIL import Image

from artifactdiff.alignment import AlignedPair, align_sequences
from artifactdiff.errors import InputValidationError, RenderUnavailableError
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
    output_dir = output_dir.expanduser().resolve()
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
                surviving = left if left is not None else right
                assert surviving is not None
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
                if surviving.render_path is None:
                    side = "before" if left is not None else "after"
                    warnings.append(
                        "Visual comparison unavailable for "
                        f"unpaired {side} page {surviving.index + 1}: rendered page missing"
                    )
                    available = False
                else:
                    area = _image_area(Path(surviving.render_path))
                    compared_pixels += area
                    weighted_changed_pixels += area
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
        with TemporaryDirectory(prefix="artifactdiff-visual-") as temporary:
            try:
                visual, temporary_assets = compare_images(
                    Path(left.render_path),
                    Path(right.render_path),
                    output_dir=Path(temporary) / key,
                    threshold=pixel_threshold,
                    tile_size=tile_size,
                )
            except (RenderUnavailableError, OSError) as error:
                warnings.append(f"Visual comparison unavailable: {error}")
                available = False
                continue
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
            copied = _copy_visual_assets(temporary_assets, output_dir / "visual" / key)
        visual_changes.append(visual)
        assets[key] = copied
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
    visual_root = destination.parent
    if visual_root.is_symlink() or destination.is_symlink():
        raise InputValidationError("visual artifact destination must not be a symlink")
    visual_root.mkdir(parents=True, exist_ok=True)
    if visual_root.is_symlink():
        raise InputValidationError("visual artifact destination must not be a symlink")
    if destination.exists():
        raise InputValidationError("visual artifact destination already exists")
    staging = Path(mkdtemp(prefix=f".{destination.name}.", dir=visual_root))
    copied = VisualAssets(
        before_image=staging / "before.png",
        after_image=staging / "after.png",
        heatmap_image=staging / "heatmap.png",
    )
    try:
        copy2(assets.before_image, copied.before_image)
        copy2(assets.after_image, copied.after_image)
        copy2(assets.heatmap_image, copied.heatmap_image)
        staging.replace(destination)
    except OSError:
        rmtree(staging)
        try:
            visual_root.rmdir()
        except OSError:
            pass
        raise
    return VisualAssets(
        before_image=destination / "before.png",
        after_image=destination / "after.png",
        heatmap_image=destination / "heatmap.png",
    )


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
