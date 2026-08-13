"""Deterministic visual page comparison orchestration."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from shutil import copy2, rmtree
from tempfile import TemporaryDirectory, mkdtemp

from PIL import Image

from artifactdiff.alignment import AlignedPair, align_sequences
from artifactdiff.errors import InputValidationError, RenderUnavailableError
from artifactdiff.models import DocumentSnapshot, PageSnapshot, Rect, VisualPageChange
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
    contract_coordinates: bool = False,
) -> VisualComparison:
    """Compare aligned rendered pages and copy changed-page artifacts."""
    output_dir = output_dir.expanduser().resolve()
    with _visual_output_lock(output_dir):
        return _compare_visual_pages(
            before,
            after,
            output_dir,
            pixel_threshold=pixel_threshold,
            tile_size=tile_size,
            include_unpaired=include_unpaired,
            contract_coordinates=contract_coordinates,
        )


def _compare_visual_pages(
    before: DocumentSnapshot,
    after: DocumentSnapshot,
    output_dir: Path,
    *,
    pixel_threshold: int,
    tile_size: int,
    include_unpaired: bool,
    contract_coordinates: bool,
) -> VisualComparison:
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
                        before_page=(
                            _page_number(left, contract_coordinates) if left is not None else None
                        ),
                        after_page=(
                            _page_number(right, contract_coordinates) if right is not None else None
                        ),
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
                    try:
                        area = _image_area(Path(surviving.render_path))
                    except OSError:
                        warnings.append(
                            "Visual comparison unavailable for "
                            f"unpaired {'before' if left is not None else 'after'} "
                            f"page {surviving.index + 1}: rendered page unavailable"
                        )
                        available = False
                    else:
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
                if contract_coordinates:
                    visual, temporary_assets = compare_images(
                        Path(left.render_path),
                        Path(right.render_path),
                        output_dir=Path(temporary) / key,
                        threshold=pixel_threshold,
                        tile_size=tile_size,
                        precise_regions=True,
                    )
                else:
                    visual, temporary_assets = compare_images(
                        Path(left.render_path),
                        Path(right.render_path),
                        output_dir=Path(temporary) / key,
                        threshold=pixel_threshold,
                        tile_size=tile_size,
                    )
                if contract_coordinates:
                    visual = visual.model_copy(
                        update={
                            "regions": _document_regions(
                                visual.regions,
                                temporary_assets.before_image,
                                left,
                                right,
                            )
                        }
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
                    "before_page": _page_number(left, contract_coordinates),
                    "after_page": _page_number(right, contract_coordinates),
                }
            )
            copied = _copy_visual_assets(temporary_assets, output_dir / "visual" / key)
            if contract_coordinates:
                copied = replace(
                    copied,
                    document_width=max(left.width, right.width),
                    document_height=max(left.height, right.height),
                )
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


def _page_number(page: PageSnapshot, contract_coordinates: bool) -> int:
    return page.index if contract_coordinates else page.index + 1


def _document_regions(
    regions: list[Rect],
    rendered_page: Path,
    before: PageSnapshot,
    after: PageSnapshot,
) -> list[Rect]:
    document_width = max(before.width, after.width)
    document_height = max(before.height, after.height)
    if document_width <= 0 or document_height <= 0:
        raise RenderUnavailableError("rendered page has invalid document dimensions")
    with Image.open(rendered_page) as image:
        if image.width <= 0 or image.height <= 0:
            raise RenderUnavailableError("rendered page has invalid pixel dimensions")
        scale_x = document_width / image.width
        scale_y = document_height / image.height
    return [
        region.model_copy(
            update={
                "x0": region.x0 * scale_x,
                "y0": region.y0 * scale_y,
                "x1": region.x1 * scale_x,
                "y1": region.y1 * scale_y,
            }
        )
        for region in regions
    ]


def _copy_visual_assets(assets: VisualAssets, destination: Path) -> VisualAssets:
    visual_root = destination.parent
    if visual_root.is_symlink() or destination.is_symlink():
        raise InputValidationError("visual artifact destination must not be a symlink")
    try:
        visual_root.mkdir(parents=True)
    except FileExistsError:
        visual_root_created = False
    else:
        visual_root_created = True
    if visual_root.is_symlink():
        raise InputValidationError("visual artifact destination must not be a symlink")
    if destination.exists() and not destination.is_dir():
        raise InputValidationError("visual artifact destination must be a directory")
    staging = Path(mkdtemp(prefix=f".{destination.name}.", dir=visual_root))
    backup: Path | None = None
    copied = VisualAssets(
        before_image=staging / "before.png",
        after_image=staging / "after.png",
        heatmap_image=staging / "heatmap.png",
    )
    try:
        copy2(assets.before_image, copied.before_image)
        copy2(assets.after_image, copied.after_image)
        copy2(assets.heatmap_image, copied.heatmap_image)
        if destination.exists():
            backup = Path(mkdtemp(prefix=f".{destination.name}.", dir=visual_root))
            backup.rmdir()
            destination.replace(backup)
        staging.replace(destination)
        if backup is not None:
            rmtree(backup)
            backup = None
    except OSError:
        if staging.exists():
            rmtree(staging)
        if backup is not None and backup.exists() and not destination.exists():
            backup.replace(destination)
        if visual_root_created:
            visual_root.rmdir()
        raise
    return VisualAssets(
        before_image=destination / "before.png",
        after_image=destination / "after.png",
        heatmap_image=destination / "heatmap.png",
    )


@contextmanager
def _visual_output_lock(output_dir: Path) -> Iterator[None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    lock = output_dir / ".artifactdiff-visual.lock"
    if lock.is_symlink():
        raise InputValidationError("visual output lock must not be a symlink")
    try:
        lock.mkdir()
    except FileExistsError:
        if lock.is_symlink():
            raise InputValidationError("visual output lock must not be a symlink") from None
        raise InputValidationError("visual output is locked") from None
    try:
        yield
    finally:
        lock.rmdir()


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
