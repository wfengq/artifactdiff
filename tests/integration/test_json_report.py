import json
from pathlib import Path

from artifactdiff.models import ComparisonResult, SourceDescriptor
from artifactdiff.reporting.json import write_json


def _unchanged_result() -> ComparisonResult:
    before = SourceDescriptor(path="前.pdf", sha256="a" * 64, format="pdf", size_bytes=10)
    after = SourceDescriptor(path="后.pdf", sha256="a" * 64, format="pdf", size_bytes=10)
    return ComparisonResult.unchanged(before, after)


def test_write_json_is_stable_utf8_schema_v1(tmp_path: Path) -> None:
    result = _unchanged_result()
    first = write_json(result, tmp_path / "first" / "report.json")
    second = write_json(result, tmp_path / "second" / "report.json")

    assert first.read_bytes() == second.read_bytes()
    text = first.read_text(encoding="utf-8")
    assert "前.pdf" in text
    assert text.startswith('{\n  "schema_version": "1.0",')
    payload = json.loads(text)
    assert payload["schema_version"] == "1.0"
    assert payload["status"] == "unchanged"
    assert not first.with_suffix(".json.tmp").exists()


def test_write_json_serializes_portable_string_paths_only(tmp_path: Path) -> None:
    result = _unchanged_result().model_copy(update={"artifacts": {"json": "report.json"}})

    report = write_json(result, tmp_path / "report.json")
    payload = json.loads(report.read_text(encoding="utf-8"))

    assert payload["artifacts"] == {"json": "report.json"}
    assert all(isinstance(payload[side]["path"], str) for side in ("before", "after"))
