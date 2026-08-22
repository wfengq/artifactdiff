"""Small cross-platform helpers for publishing complete directory trees."""

from __future__ import annotations

import os
import time
from pathlib import Path

_IS_WINDOWS = os.name == "nt"
_WINDOWS_TRANSIENT_REPLACE_ERRORS = frozenset({5, 32, 33})
_RETRY_DELAYS_SECONDS = (0.01, 0.02, 0.04, 0.08)


def replace_directory(source: Path, destination: Path) -> Path:
    """Atomically publish a directory, tolerating brief Windows scanner locks."""
    for attempt in range(len(_RETRY_DELAYS_SECONDS) + 1):
        try:
            return source.replace(destination)
        except PermissionError as error:
            transient = _IS_WINDOWS and getattr(error, "winerror", None) in (
                _WINDOWS_TRANSIENT_REPLACE_ERRORS
            )
            if not transient or attempt == len(_RETRY_DELAYS_SECONDS):
                raise
            time.sleep(_RETRY_DELAYS_SECONDS[attempt])
    raise AssertionError("directory replace retry loop exhausted")  # pragma: no cover
