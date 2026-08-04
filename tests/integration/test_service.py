from pathlib import Path
from unittest.mock import Mock

import pytest

from artifactdiff.service import CompareOptions, compare_documents
from tests.factories import make_pdf


def test_compare_documents_uses_hash_fast_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_pdf(
        tmp_path / "same.pdf",
        [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]],
    )
    monkeypatch.setattr(
        "artifactdiff.formats.base.adapter_for",
        Mock(side_effect=AssertionError("adapter called")),
    )

    run = compare_documents(source, source, tmp_path / "report", options=CompareOptions())

    assert run.result.status == "unchanged"
    assert run.result.summary.total_changes == 0
    assert run.json_path.is_file()
    assert run.html_path is not None
    assert run.html_path.is_file()
    assert run.result.artifacts == {"json": "report.json", "html": "report.html"}
    assert run.html_path.read_text(encoding="utf-8").count("data:image/") == 0
