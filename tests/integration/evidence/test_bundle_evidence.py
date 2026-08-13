from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from artifactdiff.bundle import verify_review_bundle, write_review_bundle
from artifactdiff.bundle.digests import canonical_bytes
from artifactdiff.errors import BundleError
from artifactdiff.evidence import EvidenceIndex, EvidenceItem, EvidenceKind
from artifactdiff.policy import EvidenceMode


def test_bundle_commits_supplied_evidence_and_verifier_checks_it(
    bundle_fixture: object,
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    excerpt = evidence / "excerpts" / "finding-before.txt"
    excerpt.parent.mkdir(parents=True)
    excerpt.write_text("limited excerpt", encoding="utf-8")
    index = EvidenceIndex(
        mode=EvidenceMode.MINIMAL,
        items=[
            EvidenceItem(
                kind=EvidenceKind.EXCERPT,
                path="excerpts/finding-before.txt",
                sha256=hashlib.sha256(excerpt.read_bytes()).hexdigest(),
                size_bytes=excerpt.stat().st_size,
                finding_ids=[],
                excerpt_characters=len("limited excerpt"),
            )
        ],
    )
    (evidence / "index.json").write_bytes(canonical_bytes(index))

    arguments = bundle_fixture.local_args()
    arguments["evidence"] = evidence
    bundle = write_review_bundle(**arguments)

    manifest = json.loads((bundle / "core" / "manifest.json").read_text("utf-8"))
    assert "core/evidence/excerpts/finding-before.txt" in {
        item["path"] for item in manifest["payloads"]
    }
    assert verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store).valid is True

    copied = bundle / "core" / "evidence" / "excerpts" / "finding-before.txt"
    copied.chmod(0o600)
    copied.write_text("tampered excerpt", encoding="utf-8")
    verification = verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store)
    assert verification.valid is False
    assert "payload_digest_mismatch" in verification.errors


def test_bundle_writer_rechecks_evidence_after_copy(
    bundle_fixture: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import artifactdiff.bundle.writer as bundle_writer

    evidence = tmp_path / "evidence"
    excerpt = evidence / "excerpts" / "finding-before.txt"
    excerpt.parent.mkdir(parents=True)
    excerpt.write_text("limited excerpt", encoding="utf-8")
    index = EvidenceIndex(
        mode=EvidenceMode.MINIMAL,
        items=[
            EvidenceItem(
                kind=EvidenceKind.EXCERPT,
                path="excerpts/finding-before.txt",
                sha256=hashlib.sha256(excerpt.read_bytes()).hexdigest(),
                size_bytes=excerpt.stat().st_size,
                excerpt_characters=len("limited excerpt"),
            )
        ],
    )
    (evidence / "index.json").write_bytes(canonical_bytes(index))
    original_copy = bundle_writer._copy_evidence

    def copy_then_corrupt(source: Path, destination: Path) -> None:
        original_copy(source, destination)
        destination.write_bytes(b"changed during copy")

    monkeypatch.setattr(bundle_writer, "_copy_evidence", copy_then_corrupt)
    arguments = bundle_fixture.local_args()
    arguments["evidence"] = evidence

    with pytest.raises(BundleError, match="evidence payload"):
        write_review_bundle(**arguments)

    assert list(bundle_fixture.destination.iterdir()) == []
