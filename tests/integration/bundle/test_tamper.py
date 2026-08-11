from __future__ import annotations

import stat
from pathlib import Path

import pytest

from artifactdiff.bundle import verify_review_bundle, write_review_bundle


def _mutate_one_byte(path: Path) -> None:
    path.chmod(stat.S_IWRITE | stat.S_IREAD)
    contents = bytearray(path.read_bytes())
    contents[len(contents) // 2] ^= 1
    path.write_bytes(contents)


@pytest.mark.parametrize(
    "target",
    [
        "core/policy.json",
        "core/policy.sig",
        "core/comparison.json",
        "core/facts.json",
        "core/verdict.json",
        "core/evidence/index.json",
        "core/manifest.sig",
        "events/000001-session-opened.json",
    ],
)
def test_any_payload_tamper_is_detected(bundle_fixture: object, target: str) -> None:
    bundle = write_review_bundle(
        **bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    )
    _mutate_one_byte(bundle / target)

    result = verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store)

    assert result.valid is False
    assert result.errors


def test_local_manifest_cannot_be_relabelled_as_verified(bundle_fixture: object) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    manifest = bundle / "core" / "manifest.json"
    manifest.chmod(stat.S_IWRITE | stat.S_IREAD)
    contents = manifest.read_text(encoding="utf-8")
    manifest.write_text(contents.replace('"assurance":"local"', '"assurance":"verified"'))

    result = verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store)

    assert result.valid is False


def test_complete_marker_tamper_is_detected(bundle_fixture: object) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    (bundle / "COMPLETE").write_text("0" * 64, encoding="ascii")

    result = verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store)

    assert result.valid is False


def test_revocation_preserves_historical_signature_status(bundle_fixture: object) -> None:
    bundle = write_review_bundle(
        **bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    )
    revoked_store = bundle_fixture.trust_store.model_copy(
        update={
            "identities": [
                identity.model_copy(update={"revoked": True})
                for identity in bundle_fixture.trust_store.identities
            ]
        }
    )

    result = verify_review_bundle(bundle, trust_store=revoked_store)

    assert result.valid is True
    assert result.signature_valid_at_creation is True
    assert result.currently_trusted is False
