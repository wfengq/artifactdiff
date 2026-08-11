import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

import pytest
from PIL import Image

from artifactdiff.contract import ClauseSelector, load_contract
from artifactdiff.errors import InputValidationError, PolicyValidationError
from artifactdiff.formats import adapter_for as real_adapter_for
from artifactdiff.models import ContentType, DocumentSnapshot, PageSnapshot
from artifactdiff.normalize import sha256_file
from artifactdiff.policy import (
    ContractPolicy,
    FrozenPolicy,
    PolicyPluginRequirement,
    draft_exact_replace_policy,
    freeze_policy,
    policy_digest,
)
from artifactdiff.verification.models import FindingOutcome
from artifactdiff.verification.service import VerificationOptions, verify_contract_change
from artifactdiff.visual_service import VisualComparison
from tests.factories import make_contract_docx, make_contract_pdf


class _RenderedEvidenceAdapter:
    """Preserve real parsing while supplying deterministic render evidence in tests."""

    def __init__(self, wrapped: object, *, color: str = "white") -> None:
        self.wrapped = wrapped
        self.color = color

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
        Image.new("RGB", (120, 80), self.color).save(image)
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


def _colored_rendering_adapters(
    monkeypatch: pytest.MonkeyPatch,
    colors: dict[tuple[str, str], str],
) -> None:
    monkeypatch.setattr(
        "artifactdiff.contract.service.adapter_for",
        lambda path: _RenderedEvidenceAdapter(
            real_adapter_for(path), color=colors[(path.parent.name, path.stem)]
        ),
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


_SEMANTIC_POLICY_BYPASSES = (
    "empty-expect",
    "allow-network",
    "allow-model",
    "missing-fingerprint",
    "no-op",
    "occurrence-mismatch",
)


def _redigested_semantically_invalid_frozen(frozen: FrozenPolicy, case: str) -> FrozenPolicy:
    policy = frozen.policy.model_copy(deep=True)
    if case == "empty-expect":
        policy.expect = []
    elif case in {"allow-network", "allow-model"}:
        policy.required_plugins = {
            "unsafe-plugin": PolicyPluginRequirement(
                version="1",
                distribution="unsafe-plugin",
                allow_network=case == "allow-network",
                allow_model=case == "allow-model",
            )
        }
    elif case == "missing-fingerprint":
        policy.expect[0].selector.baseline_fingerprint = ""
    elif case == "no-op":
        policy.expect[0].operation.after = policy.expect[0].operation.before
    else:
        policy.expect[0].operation.occurrences = 2
    checked = ContractPolicy.model_validate(policy)
    return FrozenPolicy(policy=checked, canonical_sha256=policy_digest(checked))


@pytest.mark.parametrize("case", _SEMANTIC_POLICY_BYPASSES)
def test_service_rejects_redigested_semantically_invalid_frozen_policy(
    tmp_path: Path, case: str
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    invalid = _redigested_semantically_invalid_frozen(frozen, case)

    with pytest.raises(PolicyValidationError):
        verify_contract_change(
            baseline,
            candidate,
            invalid,
            tmp_path / "out",
            options=VerificationOptions(visual=False),
        )


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


def test_real_pdf_visual_edit_uses_zero_based_document_coordinates(tmp_path: Path) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)

    run = verify_contract_change(
        baseline,
        candidate,
        frozen,
        tmp_path / "real-pdf-output",
        options=VerificationOptions(),
    )

    assert run.result.outcome is FindingOutcome.PASS
    payload = json.loads(run.json_path.read_text(encoding="utf-8"))
    assert payload["environment"]["visual_available"] is True
    assert run.comparison.visual_changes
    assert all(
        change.before_page == 0 and change.after_page == 0
        for change in run.comparison.visual_changes
    )
    assert all(
        region.x1 <= 612 and region.y1 <= 792
        for change in run.comparison.visual_changes
        for region in change.regions
    )
    assert any(
        finding.rule_id == "contract-safe.visual.explained" for finding in run.result.findings
    )


def test_real_pdf_visual_change_outside_expected_envelope_reviews(tmp_path: Path) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    make_contract_pdf(
        candidate,
        language="en",
        payment_days=45,
        extra_visual_mark=True,
    )

    run = verify_contract_change(
        baseline,
        candidate,
        frozen,
        tmp_path / "outside-output",
        options=VerificationOptions(),
    )

    assert run.result.outcome is FindingOutcome.REVIEW
    outside = [
        finding
        for finding in run.result.findings
        if finding.rule_id == "contract-safe.visual.outside-envelope"
    ]
    assert outside
    assert all(finding.approvable is True for finding in outside)


def test_real_pdf_signature_shift_is_nonapprovable_visual_fail(tmp_path: Path) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    make_contract_pdf(
        candidate,
        language="en",
        payment_days=45,
        signature_y_offset=18,
    )

    run = verify_contract_change(
        baseline,
        candidate,
        frozen,
        tmp_path / "signature-output",
        options=VerificationOptions(),
    )

    assert run.result.outcome is FindingOutcome.FAIL
    protected = [
        finding
        for finding in run.result.findings
        if finding.rule_id == "contract-safe.visual.protected"
    ]
    assert protected
    assert all(finding.approvable is False for finding in protected)


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


def test_nonvisual_rerun_removes_previous_visual_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "existing"
    source_root.mkdir()
    _colored_rendering_adapters(
        monkeypatch,
        {
            ("existing", "baseline"): "white",
            ("existing", "candidate"): "black",
        },
    )
    baseline, candidate, frozen = contract_edit_fixture(source_root, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    visual_run = verify_contract_change(
        baseline, candidate, frozen, output, options=VerificationOptions()
    )
    assert visual_run.visual_assets
    assert (output / "visual").is_dir()

    nonvisual_run = verify_contract_change(
        baseline,
        candidate,
        frozen,
        output,
        options=VerificationOptions(visual=False),
    )

    payload = json.loads(nonvisual_run.json_path.read_text(encoding="utf-8"))
    assert nonvisual_run.result.outcome is FindingOutcome.REVIEW
    assert payload["environment"]["visual_available"] is False
    assert payload["raw_verdict"]["outcome"] == "review"
    assert nonvisual_run.visual_assets == {}
    assert set(output.iterdir()) == {output / "verification.json"}


def test_failed_nonvisual_report_commit_restores_previous_complete_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "existing"
    source_root.mkdir()
    _colored_rendering_adapters(
        monkeypatch,
        {
            ("existing", "baseline"): "white",
            ("existing", "candidate"): "black",
        },
    )
    baseline, candidate, frozen = contract_edit_fixture(source_root, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    visual_run = verify_contract_change(
        baseline, candidate, frozen, output, options=VerificationOptions()
    )
    assert visual_run.visual_assets
    user_owned = output / "user-owned"
    user_owned.mkdir()
    (user_owned / "sentinel.txt").write_bytes(b"preserve me")
    report_before = visual_run.json_path.read_bytes()
    visual_before = {
        path.relative_to(output / "visual"): path.read_bytes()
        for path in (output / "visual").rglob("*")
        if path.is_file()
    }
    files_before = {
        path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()
    }
    directories_before = {path.relative_to(output) for path in output.rglob("*") if path.is_dir()}
    original_replace = Path.replace
    commit_observations: list[tuple[bool, int]] = []

    def fail_report_commit(source: Path, destination: Path) -> Path:
        if destination == output.resolve() / "verification.json":
            commit_observations.append(
                (
                    (output / "visual").exists(),
                    len(list(output.glob(".artifactdiff-visual-backup.*"))),
                )
            )
            raise OSError("nonvisual report commit failed")
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", fail_report_commit)

    with pytest.raises(OSError, match="nonvisual report commit failed"):
        verify_contract_change(
            baseline,
            candidate,
            frozen,
            output,
            options=VerificationOptions(visual=False),
        )

    assert commit_observations == [(False, 1)]
    assert visual_run.json_path.read_bytes() == report_before
    assert {
        path.relative_to(output / "visual"): path.read_bytes()
        for path in (output / "visual").rglob("*")
        if path.is_file()
    } == visual_before
    assert {
        path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()
    } == files_before
    assert {path.relative_to(output) for path in output.rglob("*") if path.is_dir()} == (
        directories_before
    )


def test_nonvisual_run_without_prior_visual_root_does_not_create_one(tmp_path: Path) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"

    run = verify_contract_change(
        baseline,
        candidate,
        frozen,
        output,
        options=VerificationOptions(visual=False),
    )

    assert run.json_path.is_file()
    assert not (output / "visual").exists()
    assert set(output.iterdir()) == {run.json_path}


def test_failed_nonvisual_run_without_prior_visual_root_does_not_create_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    original_replace = Path.replace

    def fail_report_commit(source: Path, destination: Path) -> Path:
        if destination == output.resolve() / "verification.json":
            raise OSError("nonvisual report commit failed")
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", fail_report_commit)

    with pytest.raises(OSError, match="nonvisual report commit failed"):
        verify_contract_change(
            baseline,
            candidate,
            frozen,
            output,
            options=VerificationOptions(visual=False),
        )

    assert not (output / "visual").exists()
    assert list(output.iterdir()) == []


def test_nonvisual_run_rejects_symlinked_visual_root_without_following_it(
    tmp_path: Path,
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    output.mkdir()
    outside = tmp_path / "outside-visual"
    outside.mkdir()
    sentinel = outside / "sentinel.png"
    sentinel.write_bytes(b"outside visual evidence")
    visual_root = output / "visual"
    try:
        visual_root.symlink_to(outside, target_is_directory=True)
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

    assert visual_root.is_symlink()
    assert sentinel.read_bytes() == b"outside visual evidence"
    assert set(output.iterdir()) == {visual_root}


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


def test_verification_lock_covers_visual_assets_through_report_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    colors = {
        ("writer-a", "baseline"): "white",
        ("writer-a", "candidate"): "black",
        ("writer-b", "baseline"): "red",
        ("writer-b", "candidate"): "blue",
    }
    _colored_rendering_adapters(monkeypatch, colors)
    first_root = tmp_path / "writer-a"
    second_root = tmp_path / "writer-b"
    first_root.mkdir()
    second_root.mkdir()
    first_baseline, first_candidate, first_frozen = contract_edit_fixture(
        first_root, "pdf", "pdf", 30, 45
    )
    second_baseline, second_candidate, second_frozen = contract_edit_fixture(
        second_root, "pdf", "pdf", 60, 75
    )
    output = tmp_path / "out"
    report_ready = Event()
    release_report = Event()
    lock_observations: list[bool] = []

    from artifactdiff.verification import service as verification_service

    real_write = verification_service.write_verification_run
    paused = False

    def pause_first_report(*args: object, **kwargs: object) -> object:
        nonlocal paused
        if not paused:
            paused = True
            lock_observations.append((output / ".artifactdiff-verification.lock").is_dir())
            report_ready.set()
            if not release_report.wait(timeout=10):
                raise RuntimeError("timed out waiting to commit first report")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(verification_service, "write_verification_run", pause_first_report)

    executor = ThreadPoolExecutor(max_workers=1)
    first_writer = executor.submit(
        verify_contract_change,
        first_baseline,
        first_candidate,
        first_frozen,
        output,
        options=VerificationOptions(),
    )
    try:
        assert report_ready.wait(timeout=10)
        second_blocked = False
        try:
            verify_contract_change(
                second_baseline,
                second_candidate,
                second_frozen,
                output,
                options=VerificationOptions(),
            )
        except InputValidationError as error:
            second_blocked = True
            assert str(error) == "verification output is locked"
    finally:
        release_report.set()
        executor.shutdown(wait=True)

    first_writer.result(timeout=10)
    payload = json.loads((output / "verification.json").read_text(encoding="utf-8"))
    assert payload["sources"]["candidate"]["sha256"] == sha256_file(first_candidate)
    with Image.open(output / "visual" / "page-1-1" / "before.png") as before_image:
        assert before_image.getpixel((0, 0)) == (255, 255, 255)
    with Image.open(output / "visual" / "page-1-1" / "after.png") as after_image:
        assert after_image.getpixel((0, 0)) == (0, 0, 0)
    assert second_blocked is True
    assert lock_observations == [True]
    assert not (output / ".artifactdiff-verification.lock").exists()
    assert not (output / ".artifactdiff-visual.lock").exists()


@pytest.mark.parametrize("lock_kind", ["directory", "symlink"])
def test_existing_verification_lock_fails_closed_without_deleting_it(
    tmp_path: Path, lock_kind: str
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    output.mkdir()
    lock = output / ".artifactdiff-verification.lock"
    outside = tmp_path / "outside-lock"
    if lock_kind == "directory":
        lock.mkdir()
    else:
        outside.mkdir()
        try:
            lock.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are unavailable in this test environment")

    with pytest.raises(InputValidationError, match="verification output (?:is locked|lock)"):
        verify_contract_change(
            baseline,
            candidate,
            frozen,
            output,
            options=VerificationOptions(visual=False),
        )

    assert lock.is_dir()
    assert lock.is_symlink() is (lock_kind == "symlink")
    assert not (output / "verification.json").exists()


@pytest.mark.parametrize(
    "failure_stage", ["contract load", "visual generation", "evaluation", "report commit"]
)
def test_failed_verification_restores_complete_output_and_releases_owned_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    colors = {
        ("existing", "baseline"): "white",
        ("existing", "candidate"): "black",
        ("failing", "baseline"): "red",
        ("failing", "candidate"): "blue",
    }
    _colored_rendering_adapters(monkeypatch, colors)
    existing_root = tmp_path / "existing"
    failing_root = tmp_path / "failing"
    existing_root.mkdir()
    failing_root.mkdir()
    existing_baseline, existing_candidate, existing_frozen = contract_edit_fixture(
        existing_root, "pdf", "pdf", 30, 45
    )
    failing_baseline, failing_candidate, failing_frozen = contract_edit_fixture(
        failing_root, "pdf", "pdf", 60, 75
    )
    output = tmp_path / "out"
    verify_contract_change(
        existing_baseline,
        existing_candidate,
        existing_frozen,
        output,
        options=VerificationOptions(),
    )
    complete_output = {
        path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()
    }
    lock = output / ".artifactdiff-verification.lock"
    lock_observations: list[bool] = []

    from artifactdiff.verification import service as verification_service

    def fail_stage(*_args: object, **_kwargs: object) -> object:
        lock_observations.append(lock.is_dir())
        raise RuntimeError(f"{failure_stage} failed")

    with monkeypatch.context() as failure:
        if failure_stage == "contract load":
            failure.setattr(verification_service, "load_contract", fail_stage)
        elif failure_stage == "visual generation":
            failure.setattr(verification_service, "compare_visual_pages", fail_stage)
        elif failure_stage == "evaluation":
            failure.setattr(verification_service, "evaluate_contract", fail_stage)
        else:
            real_replace = Path.replace

            def fail_report_replace(source: Path, destination: Path) -> Path:
                if destination == output.resolve() / "verification.json":
                    lock_observations.append(lock.is_dir())
                    raise OSError(f"{failure_stage} failed")
                return real_replace(source, destination)

            failure.setattr(Path, "replace", fail_report_replace)

        with pytest.raises((RuntimeError, OSError), match=f"{failure_stage} failed"):
            verify_contract_change(
                failing_baseline,
                failing_candidate,
                failing_frozen,
                output,
                options=VerificationOptions(),
            )

    assert {
        path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()
    } == complete_output
    assert lock_observations == [True]
    assert not lock.exists()
    assert not lock.is_symlink()

    clean_run = verify_contract_change(
        failing_baseline,
        failing_candidate,
        failing_frozen,
        output,
        options=VerificationOptions(),
    )
    clean_payload = json.loads(clean_run.json_path.read_text(encoding="utf-8"))
    assert clean_payload["sources"]["candidate"]["sha256"] == sha256_file(failing_candidate)
    assert not lock.exists()


def test_equivalent_output_path_spellings_contend_on_one_verification_lock(
    tmp_path: Path,
) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    output = tmp_path / "out"
    output.mkdir()
    lock = output / ".artifactdiff-verification.lock"
    lock.mkdir()
    equivalent_output = output / "unused-component" / ".."
    assert equivalent_output.resolve() == output.resolve()

    with pytest.raises(InputValidationError, match="locked"):
        verify_contract_change(
            baseline,
            candidate,
            frozen,
            equivalent_output,
            options=VerificationOptions(visual=False),
        )

    assert lock.is_dir()
    assert not (output / "verification.json").exists()
