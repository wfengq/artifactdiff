"""Stable JSON report serialization."""

from pathlib import Path

from artifactdiff.models import ComparisonResult


def write_json(result: ComparisonResult, path: Path) -> Path:
    """Atomically write a comparison result as indented UTF-8 JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
