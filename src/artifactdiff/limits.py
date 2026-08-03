"""Input validation and resource limits for local source documents."""

from pathlib import Path

from artifactdiff.errors import InputValidationError, ResourceLimitError, UnsupportedFormatError

MAX_BYTES = 100 * 1024 * 1024
SUPPORTED_SUFFIXES = {".pdf", ".docx"}


def validate_source(path: Path, *, force: bool, require_absolute: bool = False) -> Path:
    """Validate and resolve a supported document source path."""
    if require_absolute and not path.is_absolute():
        raise InputValidationError(f"Path must be absolute: {path}")
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise InputValidationError(f"Source is not a readable file: {resolved}")
    if resolved.suffix.casefold() not in SUPPORTED_SUFFIXES:
        raise UnsupportedFormatError(f"Supported formats are PDF and DOCX: {resolved}")
    if not force and resolved.stat().st_size > MAX_BYTES:
        raise ResourceLimitError(f"File exceeds the 100 MB limit: {resolved}")
    return resolved
