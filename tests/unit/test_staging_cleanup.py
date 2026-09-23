"""Staging directories must remain traversable while they are removed."""

import stat
from pathlib import Path
from typing import Callable

import pytest

from artifactdiff.bundle.writer import _remove_tree as remove_bundle_tree
from artifactdiff.session.service import _remove_tree as remove_session_tree


@pytest.mark.parametrize("remove_tree", [remove_bundle_tree, remove_session_tree])
def test_cleanup_keeps_directory_traversal_permission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    remove_tree: Callable[[Path], None],
) -> None:
    staging = tmp_path / "staging"
    nested = staging / "nested"
    nested.mkdir(parents=True)
    (nested / "payload.txt").write_text("payload", encoding="utf-8")
    modes: dict[Path, int] = {}
    original_chmod = Path.chmod

    def record_chmod(path: Path, mode: int) -> None:
        modes[path] = mode
        original_chmod(path, mode)

    monkeypatch.setattr(Path, "chmod", record_chmod)
    remove_tree(staging)

    assert modes[nested] & stat.S_IXUSR
    assert not staging.exists()
