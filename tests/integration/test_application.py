from __future__ import annotations

from pathlib import Path

import pytest

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import PathSafetyError, SessionError
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.session import SealedPolicyArtifact, write_sealed_policy
from artifactdiff.trust import TrustStore
from artifactdiff.verification.service import VerificationOptions
from tests.factories import make_docx


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")


def test_verification_rejects_a_symlinked_derived_run_directory(tmp_path: Path) -> None:
    """A run child under an approved output root must not redirect verification writes."""
    input_root = tmp_path / "app-input"
    output_root = tmp_path / "app-output"
    outside = tmp_path / "outside"
    input_root.mkdir()
    output_root.mkdir()
    outside.mkdir()
    (output_root / "bundle").mkdir()
    for name in ("baseline.docx", "candidate.docx", "policy.json"):
        (input_root / name).write_bytes(b"placeholder")
    _symlink_or_skip(output_root / "bundle" / "run", outside)
    application = ArtifactDiffApplication(
        trust_store=TrustStore(identities=[]),
        path_policy=PathPolicy(input_roots=(input_root,), output_roots=(output_root,)),
    )

    with pytest.raises(PathSafetyError):
        application.verify_change(
            input_root / "baseline.docx",
            input_root / "candidate.docx",
            input_root / "policy.json",
            output_root / "bundle",
            VerificationOptions(visual=False),
        )


def test_bundle_operations_accept_a_bundle_directory_inside_input_roots(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    """Using file-only input resolution would make valid Review Bundle roots unusable."""
    from artifactdiff.bundle import write_review_bundle

    bundle = write_review_bundle(**bundle_fixture.local_args())
    archives = tmp_path / "archives"
    archives.mkdir()
    application = ArtifactDiffApplication(
        trust_store=bundle_fixture.trust_store,
        path_policy=PathPolicy(
            input_roots=(bundle.parent,),
            output_roots=(archives,),
        ),
    )

    assert application.list_findings(bundle) == []
    assert application.verify_bundle(bundle).valid is True


def test_verification_rejects_a_session_directory_outside_input_roots(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    """Loading an external session could bind a verified run to an untrusted workspace."""
    input_root = tmp_path / "app-input"
    output_root = tmp_path / "app-output"
    external = tmp_path / "external-session"
    input_root.mkdir()
    output_root.mkdir()
    external.mkdir()
    for name in ("baseline.docx", "candidate.docx"):
        (input_root / name).write_bytes(b"placeholder")
    sealed_policy = write_sealed_policy(
        SealedPolicyArtifact(frozen=bundle_fixture.frozen), input_root / "policy.json"
    )
    application = ArtifactDiffApplication(
        trust_store=bundle_fixture.trust_store,
        path_policy=PathPolicy(input_roots=(input_root,), output_roots=(output_root,)),
    )

    with pytest.raises(PathSafetyError):
        application.verify_change(
            input_root / "baseline.docx",
            input_root / "candidate.docx",
            sealed_policy,
            output_root / "bundle",
            VerificationOptions(visual=False),
            session_path=external,
        )


def test_policy_validation_returns_shared_digest_and_resolved_clause_id(tmp_path: Path) -> None:
    """Adapters need the validated policy result instead of reimplementing clause selection."""
    baseline = make_docx(
        tmp_path / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="",
            heading="Payment Terms",
            anchor="Payment is due within 30 days.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, tmp_path / "policy.json")

    validated = application.validate_policy(baseline, policy_path)

    assert len(validated.policy_sha256) == 64
    assert validated.resolved_clause_id.startswith("clause-")


def test_local_verification_rejects_a_signed_policy_before_creating_output(
    bundle_fixture: object, tmp_path: Path
) -> None:
    """Resolving an output before rejecting authorization lets a race create MCP-visible state."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    inputs.mkdir()
    outputs.mkdir()
    baseline = make_docx(
        inputs / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    candidate = make_docx(
        inputs / "candidate.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 45 days."],
        rows=[["Column"]],
    )
    signed = write_sealed_policy(
        SealedPolicyArtifact(
            frozen=bundle_fixture.frozen, authorization=bundle_fixture.authorization
        ),
        inputs / "signed.json",
    )
    application = ArtifactDiffApplication(
        trust_store=bundle_fixture.trust_store,
        path_policy=PathPolicy(input_roots=(inputs,), output_roots=(outputs,)),
    )
    destination = outputs / "not-created" / "bundle"

    with pytest.raises(SessionError, match="controlled CLI or enterprise runner"):
        application.verify_local_change(
            baseline,
            candidate,
            signed,
            destination,
            VerificationOptions(visual=False),
        )

    assert not destination.parent.exists()
