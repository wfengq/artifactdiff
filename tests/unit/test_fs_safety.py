from __future__ import annotations

from pathlib import Path

import pytest

from artifactdiff.errors import PathSafetyError
from artifactdiff.fs_safety import PathPolicy


def _symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")


def test_path_policy_rejects_input_symlink_escape(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    output = tmp_path / "output"
    allowed.mkdir()
    outside.mkdir()
    output.mkdir()
    contract = outside / "contract.docx"
    contract.write_bytes(b"contract")
    link = allowed / "escape"
    _symlink_or_skip(link, outside, directory=True)
    policy = PathPolicy(input_roots=(allowed,), output_roots=(output,))

    with pytest.raises(PathSafetyError):
        policy.resolve_input(link / "contract.docx")


def test_path_policy_rejects_output_symlink_escape(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    outside = tmp_path / "outside"
    input_root.mkdir()
    output_root.mkdir()
    outside.mkdir()
    link = output_root / "escape"
    _symlink_or_skip(link, outside, directory=True)
    policy = PathPolicy(input_roots=(input_root,), output_roots=(output_root,))

    with pytest.raises(PathSafetyError):
        policy.resolve_output(link / "bundle" / "result.json")


def test_input_and_output_roots_must_be_disjoint(tmp_path: Path) -> None:
    root = tmp_path / "contracts"
    nested = root / "output"
    root.mkdir()
    nested.mkdir()

    with pytest.raises(PathSafetyError):
        PathPolicy(input_roots=(root,), output_roots=(nested,))
    with pytest.raises(PathSafetyError):
        PathPolicy(input_roots=(nested,), output_roots=(root,))


def test_output_cannot_resolve_under_an_input_root(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    policy = PathPolicy(input_roots=(input_root,), output_roots=(output_root,))

    with pytest.raises(PathSafetyError):
        policy.resolve_output(input_root / "result")


def test_output_parents_are_created_and_rechecked(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    policy = PathPolicy(input_roots=(input_root,), output_roots=(output_root,))
    destination = output_root / "sessions" / "one" / "session.json"

    resolved = policy.resolve_output(destination)

    assert resolved == destination.resolve()
    assert resolved.parent.is_dir()
    assert not resolved.exists()


def test_input_must_exist_inside_an_allowed_root(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    outside = tmp_path / "outside.docx"
    input_root.mkdir()
    output_root.mkdir()
    outside.write_bytes(b"outside")
    policy = PathPolicy(input_roots=(input_root,), output_roots=(output_root,))

    with pytest.raises(PathSafetyError):
        policy.resolve_input(outside)
    with pytest.raises(PathSafetyError):
        policy.resolve_input(input_root / "missing.docx")
