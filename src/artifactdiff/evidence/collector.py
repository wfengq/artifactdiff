"""Privacy-scoped minimal, full, and sealed evidence collection."""

from __future__ import annotations

import hashlib
import html
import json
import math
import re
import secrets
import shutil
from pathlib import Path

from PIL import Image
from pydantic import ValidationError

from artifactdiff.errors import EvidenceError
from artifactdiff.evidence.models import EvidenceIndex, EvidenceItem, EvidenceKind
from artifactdiff.models import ComparisonResult
from artifactdiff.policy import EvidenceMode
from artifactdiff.verification import RawVerdict
from artifactdiff.verification.reporting import VerificationRun

_VISUAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _item(
    root: Path,
    path: Path,
    kind: EvidenceKind,
    *,
    finding_ids: list[str] | None = None,
    excerpt_characters: int = 0,
) -> EvidenceItem:
    return EvidenceItem(
        kind=kind,
        path=path.relative_to(root).as_posix(),
        sha256=_digest(path),
        size_bytes=path.stat().st_size,
        finding_ids=sorted(finding_ids or []),
        excerpt_characters=excerpt_characters,
    )


def _copy(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise EvidenceError("evidence source is unavailable")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _verify_source_digest(source: Path, expected: str) -> None:
    if source.is_symlink() or not source.is_file() or _digest(source) != expected:
        raise EvidenceError("source contract digest does not match verification run")


def _write_full_report(source: Path, destination: Path) -> None:
    if source.suffix.casefold() in {".html", ".htm"}:
        _copy(source, destination)
        return
    if source.is_symlink() or not source.is_file():
        raise EvidenceError("verification report is unavailable")
    try:
        raw = source.read_bytes()
        if len(raw) > 10 * 1024 * 1024:
            raise EvidenceError("verification report exceeds 10 MiB limit")
        report = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceError("verification report is not UTF-8") from None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>ArtifactDiff Review</title></head><body><pre>"
        f"{html.escape(report)}"
        "</pre></body></html>",
        encoding="utf-8",
    )


def _crop_bounds(
    image: Image.Image,
    *,
    x0: float,
    y0: float,
    x1: float,
    y1: float,
    document_width: float | None,
    document_height: float | None,
) -> tuple[int, int, int, int]:
    if (document_width is None) != (document_height is None):
        raise EvidenceError("visual evidence coordinate metadata is incomplete")
    if document_width is not None and document_height is not None:
        if document_width <= 0 or document_height <= 0:
            raise EvidenceError("visual evidence coordinate metadata is invalid")
        scale_x = image.width / document_width
        scale_y = image.height / document_height
    else:
        scale_x = scale_y = 1.0
    return (
        max(0, math.floor(x0 * scale_x) - 12),
        max(0, math.floor(y0 * scale_y) - 12),
        min(image.width, math.ceil(x1 * scale_x) + 12),
        min(image.height, math.ceil(y1 * scale_y) + 12),
    )


def collect_evidence(
    run: VerificationRun,
    mode: EvidenceMode,
    destination: Path,
    *,
    baseline: Path,
    candidate: Path,
    include_sources: bool = False,
) -> EvidenceIndex:
    """Collect only evidence authorized by the explicit privacy mode."""
    try:
        checked_mode = EvidenceMode(mode)
        verdict = RawVerdict.model_validate(run.result)
        comparison = ComparisonResult.model_validate(run.comparison)
        visual_assets = dict(run.visual_assets)
    except (AttributeError, ValidationError, TypeError, ValueError):
        raise EvidenceError("invalid evidence collection input") from None
    visual_ids = [change.id for change in comparison.visual_changes]
    if any(_VISUAL_ID.fullmatch(item) is None for item in [*visual_ids, *visual_assets]):
        raise EvidenceError("visual change identifier is unsafe")
    if include_sources and checked_mode is not EvidenceMode.SEALED:
        raise EvidenceError("source contracts require sealed evidence mode")
    if destination.is_symlink() or destination.exists():
        raise EvidenceError("evidence destination must be new")
    _verify_source_digest(baseline, verdict.baseline_sha256)
    _verify_source_digest(candidate, verdict.candidate_sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.parent / f".{destination.name}.{secrets.token_hex(12)}.tmp"
    items: list[EvidenceItem] = []
    try:
        staging.mkdir()
        hashes = staging / "sources.json"
        hashes.write_text(
            json.dumps(
                {
                    "baseline_sha256": verdict.baseline_sha256,
                    "candidate_sha256": verdict.candidate_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        items.append(_item(staging, hashes, EvidenceKind.SOURCE_HASH))
        all_finding_ids = [finding.id for finding in verdict.findings]
        for finding in verdict.findings:
            for side, excerpt in (
                ("before", finding.evidence.before_excerpt),
                ("after", finding.evidence.after_excerpt),
            ):
                if excerpt is None:
                    continue
                text = excerpt[:500]
                path = staging / "excerpts" / f"{finding.id}-{side}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
                items.append(
                    _item(
                        staging,
                        path,
                        EvidenceKind.EXCERPT,
                        finding_ids=[finding.id],
                        excerpt_characters=len(text),
                    )
                )

        for change in comparison.visual_changes:
            assets = visual_assets.get(change.id)
            if assets is None:
                continue
            for region_index, region in enumerate(change.regions):
                for side, source in (
                    ("before", assets.before_image),
                    ("after", assets.after_image),
                    ("heatmap", assets.heatmap_image),
                ):
                    if source.is_symlink():
                        raise EvidenceError("visual evidence source is unsafe")
                    with Image.open(source) as image:
                        bounds = _crop_bounds(
                            image,
                            x0=region.x0,
                            y0=region.y0,
                            x1=region.x1,
                            y1=region.y1,
                            document_width=assets.document_width,
                            document_height=assets.document_height,
                        )
                        crop_path = (
                            staging / "regions" / (f"{change.id}-{region_index:04d}-{side}.png")
                        )
                        crop_path.parent.mkdir(parents=True, exist_ok=True)
                        with image.crop(bounds) as crop:
                            crop.save(crop_path, format="PNG")
                    items.append(
                        _item(
                            staging,
                            crop_path,
                            EvidenceKind.CHANGED_REGION,
                            finding_ids=all_finding_ids,
                        )
                    )

        if checked_mode in {EvidenceMode.FULL, EvidenceMode.SEALED}:
            for change_id, assets in sorted(visual_assets.items()):
                for side, source in (
                    ("before", assets.before_image),
                    ("after", assets.after_image),
                ):
                    target = staging / "pages" / f"{change_id}-{side}-page.png"
                    _copy(source, target)
                    items.append(_item(staging, target, EvidenceKind.FULL_PAGE))
            report = staging / "report" / "review.html"
            _write_full_report(run.json_path, report)
            items.append(_item(staging, report, EvidenceKind.FULL_REPORT))

        if include_sources:
            for side, source, expected_digest in (
                ("baseline", baseline, verdict.baseline_sha256),
                ("candidate", candidate, verdict.candidate_sha256),
            ):
                target = staging / "sources" / f"{side}{source.suffix.casefold()}"
                _copy(source, target)
                if _digest(target) != expected_digest:
                    raise EvidenceError(
                        "copied source contract digest does not match verification run"
                    )
                items.append(_item(staging, target, EvidenceKind.SOURCE_CONTRACT))

        index = EvidenceIndex(mode=checked_mode, items=sorted(items, key=lambda item: item.path))
        (staging / "index.json").write_text(
            json.dumps(
                index.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        staging.replace(destination)
        return index
    except EvidenceError:
        raise
    except (OSError, ValidationError, TypeError, ValueError):
        raise EvidenceError("unable to collect evidence") from None
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
