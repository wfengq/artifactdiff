import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from PIL import Image

from artifactdiff.contract import ClauseSelector, load_contract
from artifactdiff.errors import InputValidationError
from artifactdiff.formats import adapter_for as real_adapter_for
from artifactdiff.models import ContentType, DocumentSnapshot, PageSnapshot
from artifactdiff.policy import draft_exact_replace_policy, freeze_policy
from artifactdiff.verification.models import FindingOutcome
from artifactdiff.verification.service import VerificationOptions, verify_contract_change
from artifactdiff.visual_service import VisualComparison
from tests.factories import make_contract_docx, make_contract_pdf


class _RenderedEvidenceAdapter:
    """Preserve real parsing while supplying deterministic render evidence in tests."""

    def __init__(self, wrapped: object) -> None:
        self.wrapped = wrapped

    def load(
        self, path: Path, *, render: bool, workdir: Path, force: bool = False
    ) -> DocumentSnapshot:
        snapshot = self.wrapped.load(path, render=False, workdir=workdir, force=force)  # type: ignore[attr-defined]
        snapshot = snapshot.model_copy(
            update={
                "blocks": [
                    block
                    for block in snapshot.blocks
                    if block.content_type not in {ContentType.HEADER, ContentType.FOOTER}
                ],
                "metadata": {"document_features": []},
            }
        )
        if not render:
            return snapshot
        image = workdir / "test-render" / "page.png"
        image.parent.mkdir(parents=True, exist_ok=True)
        Image.new("RGB", (120, 80), "white").save(image)
        return snapshot.model_copy(
            update={
                "pages": [
                    PageSnapshot(
                        index=0,
                        width=120,
                        height=80,
                        text="contract evidence",
                        normalized_text="contract evidence",
                        render_path=str(image),
                    )
                ]
            }
        )


def _rendering_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "artifactdiff.contract.service.adapter_for",
        lambda path: _RenderedEvidenceAdapter(real_adapter_for(path)),
    )


def contract_edit_fixture(
    tmp_path: Path, baseline_format: str, candidate_format: str, before: int, after: int
) -> tuple[Path, Path, object]:
    builders = {"docx": make_contract_docx, "pdf": make_contract_pdf}
    baseline = builders[baseline_format](
        tmp_path / f"baseline.{baseline_format}", language="en", payment_days=before
    )
    candidate = builders[candidate_format](
        tmp_path / f"candidate.{candidate_format}", language="en", payment_days=after
    )
    with TemporaryDirectory(prefix="artifactdiff-test-contract-") as temporary:
        _, contract = load_contract(
            baseline, render=False, force=False, workdir=Path(temporary) / "baseline"
        )
    clause = next(item for item in contract.clauses if f"within {before} days" in item.text)
    policy = draft_exact_replace_policy(
        contract,
        ClauseSelector(
            clause_label=clause.label.normalized,
            heading=clause.heading,
            ancestor_path=clause.ancestor_path,
            anchor=f"within {before} days",
        ),
        before=f"{before} days",
        after=f"{after} days",
        rule_id="payment-window",
    )
    return baseline, candidate, freeze_policy(contract, policy)


@pytest.mark.parametrize(
    ("baseline_format", "candidate_format"),
    [("docx", "docx"), ("pdf", "pdf"), ("docx", "pdf")],
)
def test_flagship_edit_passes_all_supported_paths_with_available_visual_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    baseline_format: str,
    candidate_format: str,
) -> None:
    _rendering_adapters(monkeypatch)
    baseline, candidate, frozen = contract_edit_fixture(
        tmp_path, baseline_format, candidate_format, 30, 45
    )

    run = verify_contract_change(
        baseline, candidate, frozen, tmp_path / "out", options=VerificationOptions()
    )

    assert run.result.outcome is FindingOutcome.PASS
    payload = json.loads(run.json_path.read_text(encoding="utf-8"))
    assert payload["raw_verdict"]["outcome"] == "pass"
    assert payload["comparison"]["before"]["format"] == baseline_format
    assert payload["comparison"]["after"]["format"] == candidate_format
    assert payload["environment"]["visual_available"] is True


def test_visual_false_defaults_to_blocking_review(tmp_path: Path) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)

    run = verify_contract_change(
        baseline,
        candidate,
        frozen,
        tmp_path / "out",
        options=VerificationOptions(visual=False),
    )

    assert run.result.outcome is FindingOutcome.REVIEW
    assert any(
        finding.rule_id == "contract-safe.visual.unavailable" for finding in run.result.findings
    )
    assert run.comparison.status == "partial"
    assert (
        json.loads(run.json_path.read_text(encoding="utf-8"))["environment"]["visual_available"]
        is False
    )


def test_verification_json_is_deterministic_across_output_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _rendering_adapters(monkeypatch)
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)

    first = verify_contract_change(
        baseline, candidate, frozen, tmp_path / "first", options=VerificationOptions()
    )
    second = verify_contract_change(
        baseline, candidate, frozen, tmp_path / "second", options=VerificationOptions()
    )

    assert first.json_path.read_bytes() == second.json_path.read_bytes()
    assert b"artifactdiff-verify-" not in first.json_path.read_bytes()


def test_verification_normalizes_temporary_paths_in_public_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _rendering_adapters(monkeypatch)
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    warnings = iter(
        [
            (
                "Visual comparison unavailable: "
                "C:\\Users\\Jane Doe\\AppData\\Local\\Temp\\artifactdiff-verify-a1b2\\baseline\\page.png"
            ),
            (
                "Visual comparison unavailable: "
                "C:\\Users\\wei\\AppData\\Local\\Temp\\artifactdiff-verify-z9y8\\baseline\\page.png"
            ),
        ]
    )

    def unavailable_visual(*_args: object, **_kwargs: object) -> VisualComparison:
        return VisualComparison([], {}, [next(warnings)], 0.0, False)

    monkeypatch.setattr(
        "artifactdiff.verification.service.compare_visual_pages", unavailable_visual
    )
    first = verify_contract_change(
        baseline, candidate, frozen, tmp_path / "first", options=VerificationOptions()
    )
    second = verify_contract_change(
        baseline, candidate, frozen, tmp_path / "second", options=VerificationOptions()
    )

    first_payload = json.loads(first.json_path.read_text(encoding="utf-8"))
    assert first.json_path.read_bytes() == second.json_path.read_bytes()
    assert first_payload["warnings"] == ["Visual comparison unavailable: <temporary>"]
    assert first_payload["comparison"]["warnings"] == first_payload["warnings"]
    assert b"artifactdiff-verify-" not in first.json_path.read_bytes()


def test_verification_removes_temporary_json_on_atomic_rename_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _rendering_adapters(monkeypatch)
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("rename failed")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="rename failed"):
        verify_contract_change(
            baseline, candidate, frozen, tmp_path / "out", options=VerificationOptions()
        )

    assert not (tmp_path / "out" / "verification.json").exists()
    assert not list((tmp_path / "out").glob("*.tmp"))


def test_verification_rejects_symlinked_report_destination(tmp_path: Path) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    output.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("sentinel", encoding="utf-8")
    try:
        (output / "verification.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable in this test environment")

    with pytest.raises(InputValidationError, match="symlink"):
        verify_contract_change(
            baseline,
            candidate,
            frozen,
            output,
            options=VerificationOptions(visual=False),
        )

    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_verification_uses_unique_temp_files_without_following_legacy_temp_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    output.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("sentinel", encoding="utf-8")
    try:
        legacy_temp = output / "verification.json.tmp"
        legacy_temp.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable in this test environment")
    original_replace = Path.replace
    sources: list[str] = []

    def record_replace(source: Path, destination: Path) -> Path:
        sources.append(source.name)
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", record_replace)
    for _ in range(2):
        verify_contract_change(
            baseline,
            candidate,
            frozen,
            output,
            options=VerificationOptions(visual=False),
        )

    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert legacy_temp.is_symlink()
    assert len(sources) == 2
    assert len(set(sources)) == 2


def test_visual_verification_replaces_current_assets_when_output_is_reused(
    tmp_path: Path,
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"

    first = verify_contract_change(
        baseline, candidate, frozen, output, options=VerificationOptions()
    )
    second = verify_contract_change(
        baseline, candidate, frozen, output, options=VerificationOptions()
    )

    assert second.json_path.is_file()
    assert set(second.visual_assets) == set(first.visual_assets)
    assert all(
        path.is_file()
        for assets in second.visual_assets.values()
        for path in (assets.before_image, assets.after_image, assets.heatmap_image)
    )
    assert not [path for path in (output / "visual").iterdir() if path.name.startswith(".")]
