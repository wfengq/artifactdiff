from __future__ import annotations

import json
import stat

import pytest

from artifactdiff.bundle import (
    BundleAssurance,
    BundleError,
    verify_review_bundle,
    write_review_bundle,
)


def test_manifest_hashes_payloads_but_not_itself_or_signature(bundle_fixture: object) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    manifest = json.loads((bundle / "core" / "manifest.json").read_text(encoding="utf-8"))
    paths = {item["path"] for item in manifest["payloads"]}

    assert "core/policy.json" in paths
    assert "core/comparison.json" in paths
    assert "core/facts.json" in paths
    assert "core/verdict.json" in paths
    assert "core/evidence/index.json" in paths
    assert "core/environment.json" in paths
    assert "core/manifest.json" not in paths
    assert "core/manifest.sig" not in paths
    assert bundle.name == (bundle / "COMPLETE").read_text(encoding="ascii")


def test_verified_bundle_requires_archive_signature(bundle_fixture: object) -> None:
    with pytest.raises(BundleError, match="manifest signature"):
        write_review_bundle(**bundle_fixture.verified_args(manifest_signer=None))


@pytest.mark.parametrize("missing", ["policy_authorization", "session_event"])
def test_verified_bundle_requires_policy_and_session_proof(
    bundle_fixture: object,
    missing: str,
) -> None:
    arguments = bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    arguments[missing] = None

    with pytest.raises(BundleError):
        write_review_bundle(**arguments)


def test_enterprise_assurance_requires_an_enterprise_adapter(
    bundle_fixture: object,
) -> None:
    arguments = bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    arguments["assurance"] = BundleAssurance.ENTERPRISE

    with pytest.raises(BundleError, match="enterprise assurance"):
        write_review_bundle(**arguments)


def test_local_and_verified_assurance_have_distinct_signature_claims(
    bundle_fixture: object,
) -> None:
    local_bundle = write_review_bundle(**bundle_fixture.local_args())
    local = verify_review_bundle(local_bundle, trust_store=bundle_fixture.trust_store)
    assert local.valid is True
    assert local.assurance == "local"
    assert local.signature_valid_at_creation is None
    assert local.currently_trusted is None

    verified_bundle = write_review_bundle(
        **bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    )
    verified = verify_review_bundle(verified_bundle, trust_store=bundle_fixture.trust_store)
    assert verified.valid is True
    assert verified.assurance == "verified"
    assert verified.signature_valid_at_creation is True
    assert verified.currently_trusted is True
    assert verified.event_chain_valid is True


def test_bundle_redacts_local_source_paths(bundle_fixture: object) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    comparison = (bundle / "core" / "comparison.json").read_text(encoding="utf-8")

    assert "C:/private" not in comparison
    assert '"path":"baseline.docx"' in comparison
    assert '"path":"candidate.docx"' in comparison


def test_identical_bundle_write_is_content_addressed_and_idempotent(
    bundle_fixture: object,
) -> None:
    first = write_review_bundle(**bundle_fixture.local_args())
    second = write_review_bundle(**bundle_fixture.local_args())

    assert second == first
    assert first.is_dir()


def test_interrupted_write_leaves_no_staging_or_completed_bundle(
    bundle_fixture: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import artifactdiff.bundle.writer as bundle_writer

    original = bundle_writer._write
    calls = 0

    def fail_during_write(path: object, value: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("injected bundle write failure")
        original(path, value)

    monkeypatch.setattr(bundle_writer, "_write", fail_during_write)

    with pytest.raises(BundleError):
        write_review_bundle(**bundle_fixture.local_args())

    assert list(bundle_fixture.destination.iterdir()) == []


def test_existing_content_address_with_different_bytes_is_never_overwritten(
    bundle_fixture: object,
) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    verdict = bundle / "core" / "verdict.json"
    verdict.chmod(stat.S_IWRITE | stat.S_IREAD)
    verdict.write_bytes(verdict.read_bytes() + b" ")

    with pytest.raises(BundleError, match="collision"):
        write_review_bundle(**bundle_fixture.local_args())

    assert verdict.read_bytes().endswith(b" ")
