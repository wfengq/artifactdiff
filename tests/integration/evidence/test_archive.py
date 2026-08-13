from __future__ import annotations

import hashlib
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from artifactdiff.bundle import verify_review_bundle, write_review_bundle
from artifactdiff.bundle.digests import canonical_bytes
from artifactdiff.errors import EvidenceError
from artifactdiff.evidence import (
    EvidenceIndex,
    EvidenceItem,
    EvidenceKind,
    extract_bundle_archive,
    pack_bundle,
)
from artifactdiff.policy import EvidenceMode


@dataclass(frozen=True, slots=True)
class CopyingAgeProvider:
    fail: bool = False

    def encrypt(self, source: Path, output: Path, recipients: list[str]) -> Path:
        assert recipients == ["age1example"]
        if self.fail:
            output.write_bytes(b"partial ciphertext")
            raise EvidenceError("injected encryption failure")
        shutil.copyfile(source, output)
        return output

    def decrypt(
        self,
        source: Path,
        output: Path,
        *,
        identities: list[Path],
    ) -> Path:
        assert identities == []
        shutil.copyfile(source, output)
        return output


def test_deterministic_tar_has_sorted_normalized_members(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())

    first = pack_bundle(bundle, tmp_path / "first.tar", mode=EvidenceMode.MINIMAL)
    second = pack_bundle(bundle, tmp_path / "second.tar", mode=EvidenceMode.MINIMAL)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:") as archive:
        members = archive.getmembers()
    assert [member.name for member in members] == sorted(member.name for member in members)
    assert all(member.mtime == 0 for member in members)
    assert all(member.uid == member.gid == 0 for member in members)
    assert all(member.uname == member.gname == "" for member in members)
    assert all(member.mode == (0o700 if member.isdir() else 0o600) for member in members)


def test_sealed_archive_round_trips_to_a_verifiable_bundle(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    bundle = write_review_bundle(
        **bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    )
    archive = pack_bundle(
        bundle,
        tmp_path / "review.tar.age",
        mode=EvidenceMode.SEALED,
        recipients=["age1example"],
        age_provider=CopyingAgeProvider(),
    )

    decrypted = CopyingAgeProvider().decrypt(
        archive,
        tmp_path / "review.tar",
        identities=[],
    )
    extracted = extract_bundle_archive(decrypted, tmp_path / "extracted")
    verification = verify_review_bundle(extracted, trust_store=bundle_fixture.trust_store)

    assert verification.valid is True
    assert verification.assurance == "verified"


def test_failed_encryption_leaves_no_completed_or_temporary_archive(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    output = tmp_path / "review.tar.age"

    with pytest.raises(EvidenceError, match="injected"):
        pack_bundle(
            bundle,
            output,
            mode=EvidenceMode.SEALED,
            recipients=["age1example"],
            age_provider=CopyingAgeProvider(fail=True),
        )

    assert output.exists() is False
    assert not list(tmp_path.glob(".*review.tar.age*.tmp"))


def test_safe_extraction_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "malicious.tar"
    payload = tmp_path / "payload"
    payload.write_bytes(b"escape")
    with tarfile.open(archive, mode="w", format=tarfile.PAX_FORMAT) as stream:
        stream.add(payload, arcname="../escape", recursive=False)

    with pytest.raises(EvidenceError, match="unsafe archive member"):
        extract_bundle_archive(archive, tmp_path / "destination")

    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "destination").exists()


def test_minimal_pack_rejects_full_evidence_bundle(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "full-evidence"
    report = evidence / "report" / "review.html"
    report.parent.mkdir(parents=True)
    report.write_text("<html>full report</html>", encoding="utf-8")
    index = EvidenceIndex(
        mode=EvidenceMode.FULL,
        items=[
            EvidenceItem(
                kind=EvidenceKind.FULL_REPORT,
                path="report/review.html",
                sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
                size_bytes=report.stat().st_size,
            )
        ],
    )
    (evidence / "index.json").write_bytes(canonical_bytes(index))
    arguments = bundle_fixture.local_args()
    arguments["evidence"] = evidence
    bundle = write_review_bundle(**arguments)

    with pytest.raises(EvidenceError, match="privacy mode"):
        pack_bundle(bundle, tmp_path / "minimal.tar", mode=EvidenceMode.MINIMAL)

    assert not (tmp_path / "minimal.tar").exists()


def test_minimal_pack_rejects_unregistered_file_in_bundle(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    bundle = write_review_bundle(**bundle_fixture.local_args())
    (bundle / "unregistered-source.docx").write_bytes(b"SECRET CONTRACT")
    output = tmp_path / "minimal.tar"

    with pytest.raises(EvidenceError, match="unregistered"):
        pack_bundle(bundle, output, mode=EvidenceMode.MINIMAL)

    assert output.exists() is False
