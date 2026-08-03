from pathlib import Path

import pytest

from artifactdiff.errors import InputValidationError, ResourceLimitError
from artifactdiff.limits import validate_source


def test_validate_source_rejects_relative_path_for_mcp(tmp_path: Path) -> None:
    relative = Path("sample.pdf")

    with pytest.raises(InputValidationError, match="absolute"):
        validate_source(relative, force=False, require_absolute=True)


def test_validate_source_rejects_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "large.pdf"
    source.write_bytes(b"%PDF")
    monkeypatch.setattr("artifactdiff.limits.MAX_BYTES", 3)

    with pytest.raises(ResourceLimitError, match="100 MB"):
        validate_source(source, force=False)
