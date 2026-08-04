from pathlib import Path

import pytest

from artifactdiff.models import ComparisonResult, SourceDescriptor
from artifactdiff.reporting.json import write_json


def test_write_json_removes_temporary_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = SourceDescriptor(path="same.pdf", sha256="a" * 64, format="pdf", size_bytes=1)
    result = ComparisonResult.unchanged(descriptor, descriptor)
    report = tmp_path / "report.json"
    temporary = report.with_suffix(".json.tmp")

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("destination unavailable")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="destination unavailable"):
        write_json(result, report)

    assert not temporary.exists()
    assert not report.exists()
