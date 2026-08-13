from __future__ import annotations

import pytest
from pydantic import ValidationError

from artifactdiff.evidence import EvidenceItem, EvidenceKind


@pytest.mark.parametrize("path", ["C:secret.docx", "folder/C:secret.docx"])
def test_evidence_item_rejects_windows_drive_relative_path(path: str) -> None:
    with pytest.raises(ValidationError, match="invalid evidence path"):
        EvidenceItem(
            kind=EvidenceKind.SOURCE_CONTRACT,
            path=path,
            sha256="a" * 64,
            size_bytes=1,
        )
