from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import BaseModel

from artifactdiff.bundle import BundleManifest, BundlePayload, canonical_file_digest
from artifactdiff.bundle.digests import canonical_bytes


class SetPayload(BaseModel):
    values: frozenset[str]


def test_canonical_file_digest_hashes_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "payload.json"
    path.write_bytes(b'{"value":1}')

    assert canonical_file_digest(path) == hashlib.sha256(b'{"value":1}').hexdigest()


def test_canonical_bytes_sorts_model_sets_before_json_serialization() -> None:
    payload = SetPayload(values=frozenset({"z", "a", "m"}))

    assert canonical_bytes(payload) == b'{"values":["a","m","z"]}'


@pytest.mark.parametrize(
    "path",
    [
        "/absolute.json",
        "C:/drive.json",
        "core/../escape.json",
        "core\\policy.json",
        "policy.json",
        "events/./event.json",
        "core/nul\x00.json",
        "core/e\u0301.json",
    ],
)
def test_bundle_payload_rejects_nonportable_or_out_of_scope_paths(path: str) -> None:
    with pytest.raises(ValueError):
        BundlePayload(path=path, sha256="a" * 64, size_bytes=1)


def test_manifest_requires_unique_sorted_payload_paths() -> None:
    first = BundlePayload(path="core/verdict.json", sha256="a" * 64, size_bytes=1)
    second = BundlePayload(path="core/policy.json", sha256="b" * 64, size_bytes=1)

    with pytest.raises(ValueError):
        BundleManifest(
            assurance="local",
            baseline_sha256="a" * 64,
            candidate_sha256="b" * 64,
            policy_sha256="c" * 64,
            raw_verdict_sha256="d" * 64,
            payloads=[first, second],
            environment={},
        )
    with pytest.raises(ValueError):
        BundleManifest(
            assurance="local",
            baseline_sha256="a" * 64,
            candidate_sha256="b" * 64,
            policy_sha256="c" * 64,
            raw_verdict_sha256="d" * 64,
            payloads=[first, first],
            environment={},
        )
