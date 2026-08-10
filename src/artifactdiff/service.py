"""Application services for document comparison and inspection."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from artifactdiff.errors import InputValidationError
from artifactdiff.formats import base as format_registry
from artifactdiff.limits import validate_source
from artifactdiff.models import (
    ComparisonResult,
    ComparisonSummary,
    DocumentSnapshot,
    SemanticChange,
    SourceDescriptor,
)
from artifactdiff.reporting.html import write_html
from artifactdiff.reporting.json import write_json
from artifactdiff.semantic import diff_snapshots
from artifactdiff.visual import VisualAssets
from artifactdiff.visual_service import VisualComparison, compare_visual_pages


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
    """Compare two supported documents and write JSON and HTML reports."""
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
    visual = (
        compare_visual_pages(
            before,
            after,
            output_dir,
            pixel_threshold=options.pixel_threshold,
            tile_size=options.tile_size,
        )
        if options.visual
        else VisualComparison([], {}, _deduplicate([*before.warnings, *after.warnings]), 0.0, False)
    )
    summary = _summary(changes, visual.changed_pixel_ratio, 1)
    has_differences = bool(changes) or any(
        change.changed_pixel_ratio > 0 for change in visual.visual_changes
    )
    status: Literal["unchanged", "changed", "partial"] = (
        "partial" if visual.warnings else "changed" if has_differences else "unchanged"
    )
    result = ComparisonResult(
        status=status,
        before=_descriptor(before),
        after=_descriptor(after),
        summary=summary,
        changes=changes,
        visual_changes=visual.visual_changes,
        warnings=visual.warnings,
    )
    return _write_run(result, output_dir, visual.assets)


def _summary(changes: list[SemanticChange], ratio: float, _pixels: int) -> ComparisonSummary:
    counts = Counter(change.kind for change in changes)
    return ComparisonSummary(
        added=counts["added"],
        removed=counts["removed"],
        modified=counts["modified"],
        moved=counts["moved"],
        total_changes=len(changes),
        visual_change_ratio=ratio,
    )


def _descriptor(snapshot: DocumentSnapshot) -> SourceDescriptor:
    return SourceDescriptor(
        path=snapshot.source_path,
        sha256=snapshot.sha256,
        format=snapshot.format,
        size_bytes=snapshot.size_bytes,
    )


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
