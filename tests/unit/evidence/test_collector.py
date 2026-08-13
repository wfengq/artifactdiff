from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path

import pytest
from PIL import Image

from artifactdiff.errors import EvidenceError
from artifactdiff.evidence import collect_evidence
from artifactdiff.models import Rect, VisualPageChange
from artifactdiff.policy import EvidenceMode
from artifactdiff.verification import (
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
    finding_id,
)
from artifactdiff.visual import VisualAssets


def _verification_run(bundle_fixture: object, tmp_path: Path) -> object:
    finding = Finding(
        id=finding_id(
            rule_id="contract-safe.allow",
            rule_version="1.0",
            location="clause:evidence",
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
        ),
        rule_id="contract-safe.allow",
        outcome=FindingOutcome.REVIEW,
        location="clause:evidence",
        evidence=FindingEvidence(
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
            before_excerpt="A" * 512,
            after_excerpt="B" * 512,
        ),
        remediation="Review the evidence.",
        approvable=True,
    )
    verdict = RawVerdict(
        outcome=FindingOutcome.REVIEW,
        policy_sha256=bundle_fixture.frozen.canonical_sha256,
        baseline_sha256=bundle_fixture.run.facts.baseline_sha256,
        candidate_sha256=bundle_fixture.run.facts.candidate_sha256,
        findings=[finding],
    )
    visual_root = tmp_path / "visual-source"
    visual_root.mkdir()
    before = visual_root / "before.png"
    after = visual_root / "after.png"
    heatmap = visual_root / "heatmap.png"
    Image.new("RGB", (100, 100), "white").save(before)
    Image.new("RGB", (100, 100), "blue").save(after)
    Image.new("RGB", (100, 100), "red").save(heatmap)
    change = VisualPageChange(
        id="visual-page-1",
        before_page=0,
        after_page=0,
        changed_pixel_ratio=0.04,
        regions=[Rect(x0=20, y0=20, x1=40, y1=40)],
    )
    comparison = bundle_fixture.run.comparison.model_copy(update={"visual_changes": [change]})
    report = tmp_path / "review.html"
    report.write_text("<html>full review</html>", encoding="utf-8")
    return dataclasses.replace(
        bundle_fixture.run,
        result=verdict,
        comparison=comparison,
        json_path=report,
        visual_assets={
            change.id: VisualAssets(
                before_image=before,
                after_image=after,
                heatmap_image=heatmap,
            )
        },
    )


def _bind_source_digests(run: object, baseline: Path, candidate: Path) -> object:
    verdict = run.result.model_copy(
        update={
            "baseline_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
            "candidate_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
        }
    )
    return dataclasses.replace(run, result=verdict)


def test_minimal_evidence_omits_sources_and_full_pages(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"SECRET BASELINE")
    candidate.write_bytes(b"SECRET CANDIDATE")
    destination = tmp_path / "minimal"

    index = collect_evidence(
        _bind_source_digests(_verification_run(bundle_fixture, tmp_path), baseline, candidate),
        EvidenceMode.MINIMAL,
        destination,
        baseline=baseline,
        candidate=candidate,
    )

    assert index.mode is EvidenceMode.MINIMAL
    assert not any(
        item.kind in {"source_contract", "full_page", "full_report"} for item in index.items
    )
    assert max((item.excerpt_characters for item in index.items), default=0) <= 500
    assert any(item.kind == "changed_region" for item in index.items)
    assert b"SECRET BASELINE" not in b"".join(
        path.read_bytes() for path in destination.rglob("*") if path.is_file()
    )


def test_full_evidence_requires_explicit_mode(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"SECRET BASELINE")
    candidate.write_bytes(b"SECRET CANDIDATE")

    index = collect_evidence(
        _bind_source_digests(_verification_run(bundle_fixture, tmp_path), baseline, candidate),
        EvidenceMode.FULL,
        tmp_path / "full",
        baseline=baseline,
        candidate=candidate,
    )

    assert any(item.kind == "full_page" for item in index.items)
    assert any(item.kind == "full_report" for item in index.items)
    assert not any(item.kind == "source_contract" for item in index.items)


def test_sealed_sources_require_explicit_include_sources(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"SECRET BASELINE")
    candidate.write_bytes(b"SECRET CANDIDATE")

    index = collect_evidence(
        _bind_source_digests(_verification_run(bundle_fixture, tmp_path), baseline, candidate),
        EvidenceMode.SEALED,
        tmp_path / "sealed",
        baseline=baseline,
        candidate=candidate,
        include_sources=True,
    )

    assert [item.kind for item in index.items].count("source_contract") == 2


def test_changed_region_document_coordinates_are_scaled_to_render_pixels(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    run = _verification_run(bundle_fixture, tmp_path)
    assets = next(iter(run.visual_assets.values()))
    for path in (assets.before_image, assets.after_image, assets.heatmap_image):
        Image.new("RGB", (200, 200), "white").save(path)
    scaled_assets = VisualAssets(
        before_image=assets.before_image,
        after_image=assets.after_image,
        heatmap_image=assets.heatmap_image,
        document_width=100,
        document_height=100,
    )
    run = dataclasses.replace(
        run,
        visual_assets={next(iter(run.visual_assets)): scaled_assets},
    )
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    run = _bind_source_digests(run, baseline, candidate)

    index = collect_evidence(
        run,
        EvidenceMode.MINIMAL,
        tmp_path / "scaled",
        baseline=baseline,
        candidate=candidate,
    )

    crop_item = next(
        item
        for item in index.items
        if item.kind == "changed_region" and item.path.endswith("-before.png")
    )
    with Image.open(tmp_path / "scaled" / crop_item.path) as crop:
        assert crop.size == (64, 64)


def test_source_digest_mismatch_fails_without_publishing_evidence(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"not the bound baseline")
    candidate.write_bytes(b"not the bound candidate")
    destination = tmp_path / "mismatched"

    with pytest.raises(EvidenceError, match="digest"):
        collect_evidence(
            _verification_run(bundle_fixture, tmp_path),
            EvidenceMode.MINIMAL,
            destination,
            baseline=baseline,
            candidate=candidate,
        )

    assert destination.exists() is False


def test_full_evidence_renders_json_verification_as_html(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    run = _bind_source_digests(_verification_run(bundle_fixture, tmp_path), baseline, candidate)
    json_report = tmp_path / "verification.json"
    json_report.write_text('{"value":"<contract>"}', encoding="utf-8")
    run = dataclasses.replace(run, json_path=json_report)

    index = collect_evidence(
        run,
        EvidenceMode.FULL,
        tmp_path / "full-json",
        baseline=baseline,
        candidate=candidate,
    )

    report = next(item for item in index.items if item.kind == "full_report")
    contents = (tmp_path / "full-json" / report.path).read_text(encoding="utf-8")
    assert report.path == "report/review.html"
    assert contents.startswith("<!doctype html>")
    assert "&lt;contract&gt;" in contents


def test_sealed_source_copy_is_rechecked_against_verdict_digest(
    bundle_fixture: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import artifactdiff.evidence.collector as evidence_collector

    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    run = _bind_source_digests(_verification_run(bundle_fixture, tmp_path), baseline, candidate)
    original_copy = evidence_collector._copy

    def copy_then_corrupt(source: Path, destination: Path) -> None:
        original_copy(source, destination)
        if destination.parent.name == "sources":
            destination.write_bytes(b"changed during source copy")

    monkeypatch.setattr(evidence_collector, "_copy", copy_then_corrupt)
    destination = tmp_path / "sealed-race"

    with pytest.raises(EvidenceError, match="digest"):
        collect_evidence(
            run,
            EvidenceMode.SEALED,
            destination,
            baseline=baseline,
            candidate=candidate,
            include_sources=True,
        )

    assert destination.exists() is False


def test_visual_change_id_cannot_escape_evidence_staging(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.docx"
    candidate = tmp_path / "candidate.docx"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    run = _bind_source_digests(_verification_run(bundle_fixture, tmp_path), baseline, candidate)
    change = run.comparison.visual_changes[0].model_copy(update={"id": "../../escaped"})
    assets = next(iter(run.visual_assets.values()))
    run = dataclasses.replace(
        run,
        comparison=run.comparison.model_copy(update={"visual_changes": [change]}),
        visual_assets={change.id: assets},
    )

    with pytest.raises(EvidenceError, match="visual change identifier"):
        collect_evidence(
            run,
            EvidenceMode.MINIMAL,
            tmp_path / "unsafe-visual",
            baseline=baseline,
            candidate=candidate,
        )

    assert not list(tmp_path.glob("escaped*"))
    assert not (tmp_path / "unsafe-visual").exists()
