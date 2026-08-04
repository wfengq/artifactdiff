"""Application services for document comparison and inspection."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from shutil import copy2
from tempfile import TemporaryDirectory

from PIL import Image

from artifactdiff.alignment import align_sequences
from artifactdiff.errors import InputValidationError, RenderUnavailableError
from artifactdiff.formats import base as format_registry
from artifactdiff.limits import validate_source
from artifactdiff.models import (
    ComparisonResult,
    ComparisonSummary,
    DocumentSnapshot,
    SemanticChange,
    SourceDescriptor,
    VisualPageChange,
)
from artifactdiff.reporting.html import write_html
from artifactdiff.reporting.json import write_json
from artifactdiff.semantic import diff_snapshots
from artifactdiff.visual import VisualAssets, compare_images


@dataclass(frozen=True, slots=True)
class CompareOptions:
    """Controls parsing and deterministic visual comparison."""

    visual: bool = True
    force: bool = False
    pixel_threshold: int = 16
    tile_size: int = 32


@dataclass(frozen=True, slots=True)
class ComparisonRun:
    """Comparison result plus paths and in-process visual assets."""

    result: ComparisonResult
    json_path: Path
    html_path: Path | None = None
    visual_assets: dict[str, VisualAssets] = field(default_factory=dict)


def compare_documents(
    before: Path,
    after: Path,
    output_dir: Path,
    *,
    options: CompareOptions,
) -> ComparisonRun:
    """Compare two supported documents and write the JSON report."""
    before = validate_source(before, force=options.force)
    after = validate_source(after, force=options.force)
    if before.suffix.casefold() != after.suffix.casefold():
        raise InputValidationError("Both inputs must have the same supported format")

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    before_descriptor = SourceDescriptor.from_path(before)
    after_descriptor = SourceDescriptor.from_path(after)
    if before_descriptor.sha256 == after_descriptor.sha256:
        result = ComparisonResult.unchanged(before_descriptor, after_descriptor)
        return _write_run(result, output_dir, {})

    with TemporaryDirectory(prefix="artifactdiff-") as temporary:
        workdir = Path(temporary)
        adapter = format_registry.adapter_for(before)
        left = adapter.load(
            before,
            render=options.visual,
            workdir=workdir / "before",
            force=options.force,
        )
        right = adapter.load(
            after,
            render=options.visual,
            workdir=workdir / "after",
            force=options.force,
        )
        return _compare_snapshots(left, right, output_dir, workdir, options)


def inspect_document(
    path: Path,
    *,
    force: bool = False,
    require_absolute: bool = False,
    max_blocks: int = 100,
) -> dict[str, object]:
    """Return a bounded portable structural summary for one document."""
    if max_blocks < 0:
        raise InputValidationError("max_blocks must be non-negative")
    source = validate_source(path, force=force, require_absolute=require_absolute)
    with TemporaryDirectory(prefix="artifactdiff-inspect-") as temporary:
        snapshot = format_registry.adapter_for(source).load(
            source,
            render=False,
            workdir=Path(temporary) / "source",
            force=force,
        )
    return {
        "path": snapshot.source_path,
        "format": snapshot.format,
        "sha256": snapshot.sha256,
        "size_bytes": snapshot.size_bytes,
        "page_count": snapshot.page_count,
        "metadata": snapshot.metadata,
        "blocks": [block.model_dump(mode="json") for block in snapshot.blocks[:max_blocks]],
        "warnings": list(snapshot.warnings),
        "truncated": len(snapshot.blocks) > max_blocks,
    }


def _compare_snapshots(
    before: DocumentSnapshot,
    after: DocumentSnapshot,
    output_dir: Path,
    workdir: Path,
    options: CompareOptions,
) -> ComparisonRun:
    changes = diff_snapshots(before, after)
    warnings = _deduplicate([*before.warnings, *after.warnings])
    visual_changes: list[VisualPageChange] = []
    visual_assets: dict[str, VisualAssets] = {}
    weighted_changed_pixels = 0.0
    compared_pixels = 0

    if options.visual:
        page_pairs = align_sequences(
            before.pages,
            after.pages,
            key=lambda page: page.normalized_text,
        )
        page_pairs.sort(
            key=lambda pair: (
                pair.before.index if pair.before is not None else pair.after.index,
                pair.after.index if pair.after is not None else pair.before.index,
            )
        )
        for pair in page_pairs:
            left = pair.before
            right = pair.after
            if left is None or right is None:
                continue
            if left.render_path is None or right.render_path is None:
                warnings.append(
                    "Visual comparison unavailable for "
                    f"before page {left.index + 1} and after page {right.index + 1}: "
                    "rendered page missing"
                )
                continue
            key = f"page-{left.index + 1}-{right.index + 1}"
            try:
                visual, temporary_assets = compare_images(
                    Path(left.render_path),
                    Path(right.render_path),
                    output_dir=workdir / "visual" / key,
                    threshold=options.pixel_threshold,
                    tile_size=options.tile_size,
                )
            except (RenderUnavailableError, OSError) as error:
                warnings.append(f"Visual comparison unavailable: {error}")
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
            visual_changes.append(visual)
            visual_assets[key] = _copy_visual_assets(temporary_assets, output_dir / "visual" / key)

    summary = _summary(changes, weighted_changed_pixels, compared_pixels)
    warnings = _deduplicate(warnings)
    has_differences = bool(changes) or any(
        change.changed_pixel_ratio > 0 for change in visual_changes
    )
    status = "partial" if warnings else "changed" if has_differences else "unchanged"
    result = ComparisonResult(
        status=status,
        before=_descriptor(before),
        after=_descriptor(after),
        summary=summary,
        changes=changes,
        visual_changes=visual_changes,
        warnings=warnings,
    )
    return _write_run(result, output_dir, visual_assets)


def _summary(changes: list[SemanticChange], weighted: float, pixels: int) -> ComparisonSummary:
    counts = Counter(change.kind for change in changes)
    return ComparisonSummary(
        added=counts["added"],
        removed=counts["removed"],
        modified=counts["modified"],
        moved=counts["moved"],
        total_changes=len(changes),
        visual_change_ratio=weighted / pixels if pixels else 0.0,
    )


def _descriptor(snapshot: DocumentSnapshot) -> SourceDescriptor:
    return SourceDescriptor(
        path=snapshot.source_path,
        sha256=snapshot.sha256,
        format=snapshot.format,
        size_bytes=snapshot.size_bytes,
    )


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


def _image_area(path: Path) -> int:
    with Image.open(path) as image:
        return image.width * image.height


def _deduplicate(warnings: list[str]) -> list[str]:
    return list(dict.fromkeys(warnings))


def _write_run(
    result: ComparisonResult,
    output_dir: Path,
    visual_assets: dict[str, VisualAssets],
) -> ComparisonRun:
    result = result.model_copy(update={"artifacts": {"json": "report.json", "html": "report.html"}})
    html_path = write_html(result, visual_assets, output_dir / "report.html")
    json_path = write_json(result, output_dir / "report.json")
    return ComparisonRun(
        result=result,
        json_path=json_path,
        html_path=html_path,
        visual_assets=visual_assets,
    )
