"""Shared interface and lookup for document format adapters."""

from pathlib import Path
from typing import Protocol

from artifactdiff.errors import UnsupportedFormatError
from artifactdiff.models import DocumentSnapshot


class FormatAdapter(Protocol):
    """Load a supported document into a portable snapshot."""

    def load(
        self, path: Path, *, render: bool, workdir: Path, force: bool = False
    ) -> DocumentSnapshot:
        """Load one source document."""
        raise NotImplementedError


def adapter_for(path: Path) -> FormatAdapter:
    """Return the adapter selected by a source path's extension."""
    suffix = path.suffix.casefold()
    if suffix == ".pdf":
        from artifactdiff.formats.pdf import PdfAdapter

        return PdfAdapter()
    if suffix == ".docx":
        from artifactdiff.formats.docx import DocxAdapter

        return DocxAdapter()
    raise UnsupportedFormatError(f"Supported formats are PDF and DOCX: {path}")
