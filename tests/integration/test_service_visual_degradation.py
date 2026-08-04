from pathlib import Path
from unittest.mock import Mock

import pytest

from artifactdiff.models import DocumentSnapshot
from artifactdiff.service import CompareOptions, compare_documents
from tests.integration.test_service_orchestration import (
    FakeAdapter,
    _different_pdf_paths,
    _snapshot,
)


class MissingRenderAdapter(FakeAdapter):
    def load(
        self, path: Path, *, render: bool, workdir: Path, force: bool = False
    ) -> DocumentSnapshot:
        self.calls.append((path, render, workdir, force))
        return _snapshot(
            path,
            workdir,
            texts=self.texts[path.name],
            render=False,
        )


def test_missing_paired_render_returns_partial_without_losing_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = MissingRenderAdapter(
        texts={"before.pdf": ["Revenue 100"], "after.pdf": ["Revenue 101"]}
    )
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)

    run = compare_documents(before, after, tmp_path / "report", options=CompareOptions())

    assert run.result.status == "partial"
    assert run.result.summary.modified == 1
    assert run.result.warnings == [
        "Visual comparison unavailable for before page 1 and after page 1: rendered page missing"
    ]


def test_visual_image_error_returns_partial_without_losing_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _different_pdf_paths(tmp_path)
    adapter = FakeAdapter(texts={"before.pdf": ["Revenue 100"], "after.pdf": ["Revenue 101"]})
    monkeypatch.setattr("artifactdiff.formats.base.adapter_for", lambda _: adapter)
    monkeypatch.setattr(
        "artifactdiff.service.compare_images",
        Mock(side_effect=OSError("rendered image unreadable")),
    )

    run = compare_documents(before, after, tmp_path / "report", options=CompareOptions())

    assert run.result.status == "partial"
    assert run.result.summary.modified == 1
    assert run.result.warnings == ["Visual comparison unavailable: rendered image unreadable"]
