"""Deterministic pixel-level visual comparisons."""

from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageChops

from artifactdiff.models import Rect, VisualPageChange


@dataclass(frozen=True, slots=True)
class VisualAssets:
    """PNG assets produced for a single visual comparison."""

    before_image: Path
    after_image: Path
    heatmap_image: Path
    document_width: float | None = None
    document_height: float | None = None


def compare_images(
    before: Path,
    after: Path,
    *,
    output_dir: Path,
    threshold: int = 16,
    tile_size: int = 32,
    precise_regions: bool = False,
) -> tuple[VisualPageChange, VisualAssets]:
    """Compare two images on a shared white canvas and write deterministic assets."""
    threshold = max(0, min(255, threshold))
    tile_size = max(8, min(256, tile_size))

    with ExitStack() as resources:
        before_source = resources.enter_context(Image.open(before))
        after_source = resources.enter_context(Image.open(after))
        before_rgb = resources.enter_context(before_source.convert("RGB"))
        after_rgb = resources.enter_context(after_source.convert("RGB"))
        left, right = _common_canvas(before_rgb, after_rgb)
        resources.callback(left.close)
        resources.callback(right.close)

        rgb_difference = resources.enter_context(ImageChops.difference(left, right))
        difference = resources.enter_context(rgb_difference.convert("L"))
        pixel_mask = resources.enter_context(
            difference.point(lambda value: 255 if value > threshold else 0)
        )
        extent_mask = resources.enter_context(
            _extent_difference(before_rgb.size, after_rgb.size, left.size)
        )
        mask = resources.enter_context(ImageChops.lighter(pixel_mask, extent_mask))
        changed_pixels = mask.histogram()[255]
        ratio = changed_pixels / (mask.width * mask.height)
        regions = _coalesced_tile_regions(mask, tile_size, precise_bounds=precise_regions)
        heatmap = resources.enter_context(_heatmap(right, mask))
        return _write_visual_result(left, right, heatmap, regions, ratio, output_dir)


def _common_canvas(left: Image.Image, right: Image.Image) -> tuple[Image.Image, Image.Image]:
    size = (max(left.width, right.width), max(left.height, right.height))
    left_canvas = Image.new("RGB", size, "white")
    right_canvas = Image.new("RGB", size, "white")
    left_canvas.paste(left, (0, 0))
    right_canvas.paste(right, (0, 0))
    return left_canvas, right_canvas


def _extent_difference(
    left_size: tuple[int, int],
    right_size: tuple[int, int],
    canvas_size: tuple[int, int],
) -> Image.Image:
    left_extent = Image.new("L", canvas_size, 0)
    right_extent = Image.new("L", canvas_size, 0)
    try:
        left_extent.paste(255, (0, 0, *left_size))
        right_extent.paste(255, (0, 0, *right_size))
        return ImageChops.difference(left_extent, right_extent)
    finally:
        left_extent.close()
        right_extent.close()


def _coalesced_tile_regions(
    mask: Image.Image, tile_size: int, *, precise_bounds: bool = False
) -> list[Rect]:
    horizontal: list[tuple[int, int, int, int]] = []
    for y0 in range(0, mask.height, tile_size):
        y1 = min(y0 + tile_size, mask.height)
        current: tuple[int, int, int, int] | None = None
        for x0 in range(0, mask.width, tile_size):
            x1 = min(x0 + tile_size, mask.width)
            with mask.crop((x0, y0, x1, y1)) as tile:
                bounds = tile.getbbox()
            if bounds is not None:
                rectangle = (
                    (
                        x0 + bounds[0],
                        y0 + bounds[1],
                        x0 + bounds[2],
                        y0 + bounds[3],
                    )
                    if precise_bounds
                    else (x0, y0, x1, y1)
                )
                if current is None:
                    current = rectangle
                else:
                    current = (
                        current[0],
                        min(current[1], rectangle[1]),
                        rectangle[2],
                        max(current[3], rectangle[3]),
                    )
            elif current is not None:
                horizontal.append(current)
                current = None
        if current is not None:
            horizontal.append(current)

    merged: list[tuple[int, int, int, int]] = []
    active: dict[tuple[int, int], tuple[int, int, int, int]] = {}
    rows: dict[int, list[tuple[int, int, int, int]]] = {}
    for rectangle in horizontal:
        rows.setdefault(rectangle[1], []).append(rectangle)
    for y0 in sorted(rows):
        current_keys = {(rectangle[0], rectangle[2]) for rectangle in rows[y0]}
        for key in sorted(set(active) - current_keys):
            merged.append(active.pop(key))
        for rectangle in rows[y0]:
            key = (rectangle[0], rectangle[2])
            previous = active.get(key)
            if previous is not None and previous[3] == rectangle[1]:
                active[key] = (previous[0], previous[1], previous[2], rectangle[3])
            else:
                if previous is not None:
                    merged.append(previous)
                active[key] = rectangle
    merged.extend(active.values())
    merged.sort(key=lambda rectangle: (rectangle[1], rectangle[0], rectangle[3], rectangle[2]))
    return [Rect(x0=x0, y0=y0, x1=x1, y1=y1) for x0, y0, x1, y1 in merged]


def _heatmap(after: Image.Image, mask: Image.Image) -> Image.Image:
    highlight = Image.new("RGB", after.size, (255, 0, 0))
    try:
        return Image.composite(highlight, after, mask)
    finally:
        highlight.close()


def _write_visual_result(
    before: Image.Image,
    after: Image.Image,
    heatmap: Image.Image,
    regions: list[Rect],
    ratio: float,
    output_dir: Path,
) -> tuple[VisualPageChange, VisualAssets]:
    output_dir.mkdir(parents=True, exist_ok=True)
    assets = VisualAssets(
        before_image=output_dir / "before.png",
        after_image=output_dir / "after.png",
        heatmap_image=output_dir / "heatmap.png",
    )
    before.save(assets.before_image, format="PNG")
    after.save(assets.after_image, format="PNG")
    heatmap.save(assets.heatmap_image, format="PNG")
    change = VisualPageChange(
        id="visual",
        changed_pixel_ratio=ratio,
        regions=regions,
    )
    return change, assets
