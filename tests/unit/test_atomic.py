from __future__ import annotations

from pathlib import Path

import pytest


def _sharing_violation() -> PermissionError:
    error = PermissionError("synthetic Windows sharing violation")
    error.winerror = 32  # type: ignore[attr-defined]
    return error


def test_directory_publish_retries_transient_windows_sharing_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from artifactdiff import atomic

    attempts = 0
    sleeps: list[float] = []
    target = Path("published")

    def replace(_source: Path, destination: Path) -> Path:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise _sharing_violation()
        return destination

    monkeypatch.setattr(atomic, "_IS_WINDOWS", True)
    monkeypatch.setattr(Path, "replace", replace)
    monkeypatch.setattr(atomic.time, "sleep", sleeps.append)

    assert atomic.replace_directory(Path("staging"), target) == target
    assert attempts == 3
    assert sleeps == [0.01, 0.02]


def test_directory_publish_does_not_retry_nontransient_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from artifactdiff import atomic

    attempts = 0

    def replace(_source: Path, _destination: Path) -> Path:
        nonlocal attempts
        attempts += 1
        raise OSError("synthetic permanent failure")

    monkeypatch.setattr(atomic, "_IS_WINDOWS", True)
    monkeypatch.setattr(Path, "replace", replace)
    monkeypatch.setattr(
        atomic.time,
        "sleep",
        lambda _delay: pytest.fail("permanent errors must not be retried"),
    )

    with pytest.raises(OSError, match="permanent failure"):
        atomic.replace_directory(Path("staging"), Path("published"))
    assert attempts == 1
