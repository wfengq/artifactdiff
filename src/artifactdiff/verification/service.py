"""Cross-format, contract-safe verification orchestration."""

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from artifactdiff.contract import load_contract
from artifactdiff.errors import InputValidationError, PolicyValidationError
from artifactdiff.limits import validate_source
from artifactdiff.models import (
    ComparisonResult,
    ComparisonSummary,
    DocumentSnapshot,
    SourceDescriptor,
)
from artifactdiff.normalize import sha256_file
from artifactdiff.policy.models import FrozenPolicy
from artifactdiff.semantic import diff_snapshots
from artifactdiff.verification import diff_contracts, evaluate_contract
from artifactdiff.verification.reporting import VerificationRun, write_verification_run
from artifactdiff.visual_service import VisualComparison, compare_visual_pages

SUPPORTED_VERIFICATION_PAIRS = frozenset({(".docx", ".docx"), (".pdf", ".pdf"), (".docx", ".pdf")})


@dataclass(frozen=True, slots=True)
class VerificationOptions:
    """Controls deterministic visual evidence for contract verification."""

    visual: bool = True
    pixel_threshold: int = 16
    tile_size: int = 32


def verify_contract_change(
    baseline: Path,
    candidate: Path,
    frozen_policy: FrozenPolicy,
    output_dir: Path,
    *,
    options: VerificationOptions,
) -> VerificationRun:
    """Verify one exact contract edit without network, model, or approval steps."""
    checked_baseline = validate_source(baseline, force=False)
    checked_candidate = validate_source(candidate, force=False)
    if frozen_policy.policy.baseline.sha256 != sha256_file(checked_baseline):
        raise PolicyValidationError("baseline hash does not match frozen policy")
    pair = (checked_baseline.suffix.casefold(), checked_candidate.suffix.casefold())
    if pair not in SUPPORTED_VERIFICATION_PAIRS:
        raise InputValidationError(
            "supported verification paths are DOCX-to-DOCX, PDF-to-PDF, and DOCX-to-PDF"
        )
    with TemporaryDirectory(prefix="artifactdiff-verify-") as temporary:
        workdir = Path(temporary)
        baseline_snapshot, baseline_contract = load_contract(
            checked_baseline,
            render=options.visual,
            force=False,
            workdir=workdir / "baseline",
        )
        candidate_snapshot, candidate_contract = load_contract(
            checked_candidate,
            render=options.visual,
            force=False,
            workdir=workdir / "candidate",
        )
        visual = _visual_comparison(
            baseline_snapshot,
            candidate_snapshot,
            output_dir,
            options,
        )
        facts = diff_contracts(baseline_contract, candidate_contract)
        verdict = evaluate_contract(
            frozen_policy,
            baseline_contract,
            candidate_contract,
            facts,
            visual.visual_changes,
            visual.available,
        )
        comparison = _comparison_result(
            baseline_snapshot,
            candidate_snapshot,
            visual,
        )
        return write_verification_run(
            verdict,
            facts,
            visual,
            output_dir,
            comparison=comparison,
            frozen_policy=frozen_policy,
        )


def _visual_comparison(
    baseline: DocumentSnapshot,
    candidate: DocumentSnapshot,
    output_dir: Path,
    options: VerificationOptions,
) -> VisualComparison:
    if not options.visual:
        return VisualComparison(
            [], {}, _deduplicate([*baseline.warnings, *candidate.warnings]), 0.0, False
        )
    return compare_visual_pages(
        baseline,
        candidate,
        output_dir,
        pixel_threshold=options.pixel_threshold,
        tile_size=options.tile_size,
        include_unpaired=True,
    )


def _comparison_result(
    baseline: DocumentSnapshot,
    candidate: DocumentSnapshot,
    visual: VisualComparison,
) -> ComparisonResult:
    changes = diff_snapshots(baseline, candidate)
    has_differences = bool(changes) or bool(visual.visual_changes)
    return ComparisonResult(
        status=(
            "partial"
            if visual.warnings or not visual.available
            else "changed"
            if has_differences
            else "unchanged"
        ),
        before=_descriptor(baseline),
        after=_descriptor(candidate),
        summary=ComparisonSummary(
            added=sum(change.kind == "added" for change in changes),
            removed=sum(change.kind == "removed" for change in changes),
            modified=sum(change.kind == "modified" for change in changes),
            moved=sum(change.kind == "moved" for change in changes),
            total_changes=len(changes),
            visual_change_ratio=visual.changed_pixel_ratio,
        ),
        changes=changes,
        visual_changes=visual.visual_changes,
        warnings=visual.warnings,
        artifacts={"json": "verification.json"},
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
