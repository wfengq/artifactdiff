from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from artifactdiff.errors import EncryptionUnavailableError, EvidenceError
from artifactdiff.evidence import AgeCliProvider


def test_age_uses_argument_list_without_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "bundle.tar"
    output = tmp_path / "bundle.tar.age"
    source.write_bytes(b"archive")
    calls: list[tuple[list[str], bool]] = []

    def completed(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, bool(kwargs["shell"])))
        output.write_bytes(b"encrypted")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", completed)

    AgeCliProvider(Path("age")).encrypt(source, output, ["age1example"])

    assert calls == [
        (
            ["age", "-r", "age1example", "-o", str(output), str(source)],
            False,
        )
    ]


def test_missing_age_has_an_actionable_public_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "bundle.tar"
    source.write_bytes(b"archive")

    def missing(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)

    with pytest.raises(
        EncryptionUnavailableError,
        match="Install age and ensure the 'age' executable is on PATH.",
    ):
        AgeCliProvider(Path("age")).encrypt(
            source,
            tmp_path / "bundle.tar.age",
            ["age1example"],
        )


@pytest.mark.parametrize("failure", ["nonzero", "missing_output", "timeout"])
def test_age_failure_removes_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    source = tmp_path / "bundle.tar"
    output = tmp_path / "bundle.tar.age"
    source.write_bytes(b"archive")

    def fail(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if failure != "missing_output":
            output.write_bytes(b"partial")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 300)
        return subprocess.CompletedProcess(args, 1 if failure == "nonzero" else 0, "", "")

    monkeypatch.setattr(subprocess, "run", fail)

    with pytest.raises(EvidenceError, match="timed out|encryption failed"):
        AgeCliProvider(Path("age")).encrypt(source, output, ["age1example"])

    assert output.exists() is False


def test_age_decrypt_uses_argument_list_without_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "bundle.tar.age"
    output = tmp_path / "bundle.tar"
    identity = tmp_path / "identity.txt"
    source.write_bytes(b"encrypted")
    identity.write_text("AGE-SECRET-KEY", encoding="utf-8")
    calls: list[tuple[list[str], bool]] = []

    def completed(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, bool(kwargs["shell"])))
        output.write_bytes(b"archive")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", completed)

    AgeCliProvider(Path("age")).decrypt(source, output, identities=[identity])

    assert calls == [
        (
            ["age", "-d", "-i", str(identity), "-o", str(output), str(source)],
            False,
        )
    ]
