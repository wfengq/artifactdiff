from pathlib import Path

import pytest
from docx import Document

import artifactdiff.formats.docx as docx_module
from artifactdiff.errors import InputValidationError, RenderUnavailableError
from artifactdiff.formats.docx import DocxAdapter
from artifactdiff.models import ContentType
from tests.factories import make_docx, make_pdf


def test_docx_adapter_preserves_heading_paragraph_table_order(tmp_path: Path) -> None:
    source = make_docx(
        tmp_path / "sample.docx",
        heading="Q2 Results",
        paragraphs=["Revenue increased."],
        rows=[["Region", "Total"], ["APAC", "100"]],
    )

    snapshot = DocxAdapter().load(source, render=False, workdir=tmp_path / "work")

    assert [block.content_type for block in snapshot.blocks[:3]] == [
        ContentType.HEADING,
        ContentType.PARAGRAPH,
        ContentType.TABLE,
    ]
    assert snapshot.blocks[0].metadata["level"] == 1
    assert snapshot.blocks[2].text == "Region\tTotal\nAPAC\t100"
    assert snapshot.blocks[2].metadata == {"rows": 2, "columns": 2}


def test_docx_adapter_serializes_bounded_document_features(tmp_path: Path) -> None:
    source = tmp_path / "metadata.docx"
    document = Document()
    document.core_properties.author = "Private Fixture Author"
    document.add_paragraph("Terms")
    document.save(source)

    snapshot = DocxAdapter().load(source, render=False, workdir=tmp_path / "work")

    facts = snapshot.metadata["document_features"]
    assert isinstance(facts, list)
    assert any(item["kind"] == "metadata" for item in facts)
    assert "Private Fixture Author" not in str(facts)


def test_docx_adapter_preserves_lists_with_stable_dense_block_identity(tmp_path: Path) -> None:
    source = tmp_path / "lists.docx"
    document = Document()
    document.add_paragraph("")
    document.add_paragraph("Review revenue", style="List Bullet")
    document.add_paragraph("Approve forecast", style="List Number")
    document.save(source)

    first = DocxAdapter().load(source, render=False, workdir=tmp_path / "first")
    second = DocxAdapter().load(source, render=False, workdir=tmp_path / "second")

    assert [block.text for block in first.blocks] == ["Review revenue", "Approve forecast"]
    assert [block.content_type for block in first.blocks] == [
        ContentType.PARAGRAPH,
        ContentType.PARAGRAPH,
    ]
    assert [block.metadata for block in first.blocks] == [
        {"list_kind": "bullet", "level": 1},
        {"list_kind": "number", "level": 1},
    ]
    assert [block.ordinal for block in first.blocks] == [0, 1]
    assert [block.id for block in first.blocks] == [block.id for block in second.blocks]


def test_docx_adapter_appends_unique_non_empty_headers_and_footers(tmp_path: Path) -> None:
    source = tmp_path / "sections.docx"
    document = Document()
    document.add_paragraph("Body text")
    document.sections[0].header.paragraphs[0].text = "Quarterly report"
    document.sections[0].footer.paragraphs[0].text = "Confidential"
    document.add_section()
    document.save(source)

    snapshot = DocxAdapter().load(source, render=False, workdir=tmp_path / "work")

    assert [block.content_type for block in snapshot.blocks] == [
        ContentType.PARAGRAPH,
        ContentType.HEADER,
        ContentType.FOOTER,
    ]
    assert [block.text for block in snapshot.blocks] == [
        "Body text",
        "Quarterly report",
        "Confidential",
    ]
    assert [block.ordinal for block in snapshot.blocks] == [0, 1, 2]


def test_docx_adapter_rejects_corrupt_docx_with_domain_error(tmp_path: Path) -> None:
    source = tmp_path / "broken.docx"
    source.write_bytes(b"not an OOXML package")

    with pytest.raises(InputValidationError, match="invalid DOCX") as error:
        DocxAdapter().load(source, render=False, workdir=tmp_path / "work")

    assert str(source) in str(error.value)


def test_docx_render_without_libreoffice_keeps_semantics_and_adds_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_docx(
        tmp_path / "sample.docx",
        heading="Q2 Results",
        paragraphs=["Revenue increased."],
        rows=[["Region", "Total"]],
    )
    monkeypatch.setattr(docx_module, "find_libreoffice", lambda: None, raising=False)

    snapshot = DocxAdapter().load(source, render=True, workdir=tmp_path / "work")

    assert [block.text for block in snapshot.blocks[:2]] == [
        "Q2 Results",
        "Revenue increased.",
    ]
    assert snapshot.pages == []
    assert snapshot.page_count is None
    assert len(snapshot.warnings) == 1
    assert "LibreOffice was not found" in snapshot.warnings[0]


def test_docx_render_conversion_failure_keeps_semantics_and_adds_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_docx(
        tmp_path / "sample.docx",
        heading="Q2 Results",
        paragraphs=["Revenue increased."],
        rows=[["Region", "Total"]],
    )
    executable = tmp_path / "soffice"
    monkeypatch.setattr(docx_module, "find_libreoffice", lambda: executable)

    def fail_conversion(*args: object, **kwargs: object) -> Path:
        raise RenderUnavailableError("LibreOffice timed out")

    monkeypatch.setattr(docx_module, "convert_docx_to_pdf", fail_conversion, raising=False)

    snapshot = DocxAdapter().load(source, render=True, workdir=tmp_path / "work")

    assert snapshot.blocks[0].text == "Q2 Results"
    assert snapshot.pages == []
    assert snapshot.warnings == ["DOCX visual rendering unavailable: LibreOffice timed out"]


def test_docx_render_reuses_pdf_adapter_pages_and_retains_logical_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_docx(
        tmp_path / "sample.docx",
        heading="Q2 Results",
        paragraphs=["Revenue increased."],
        rows=[["Region", "Total"]],
    )
    converted = make_pdf(
        tmp_path / "sample.pdf",
        [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]],
    )
    monkeypatch.setattr(docx_module, "find_libreoffice", lambda: tmp_path / "soffice")
    monkeypatch.setattr(
        docx_module,
        "convert_docx_to_pdf",
        lambda source, output_dir, executable: converted,
    )

    snapshot = DocxAdapter().load(source, render=True, workdir=tmp_path / "work")

    assert snapshot.page_count == 2
    assert [page.text for page in snapshot.pages] == ["Revenue 100", "Notes"]
    assert all(Path(page.render_path).is_file() for page in snapshot.pages)
    assert [block.content_type for block in snapshot.blocks[:3]] == [
        ContentType.HEADING,
        ContentType.PARAGRAPH,
        ContentType.TABLE,
    ]
    assert snapshot.warnings == []


def test_docx_render_output_directory_error_keeps_semantics_and_adds_one_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_docx(
        tmp_path / "sample.docx",
        heading="Q2 Results",
        paragraphs=["Revenue increased."],
        rows=[["Region", "Total"]],
    )
    workdir = tmp_path / "render-work"
    blocked_output_dir = workdir / "libreoffice"
    original_mkdir = Path.mkdir

    def fail_output_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        if path == blocked_output_dir:
            raise PermissionError("read-only render workdir")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_output_mkdir)
    monkeypatch.setattr(docx_module, "find_libreoffice", lambda: tmp_path / "soffice")

    snapshot = DocxAdapter().load(source, render=True, workdir=workdir)

    assert [block.text for block in snapshot.blocks[:2]] == [
        "Q2 Results",
        "Revenue increased.",
    ]
    assert snapshot.pages == []
    assert snapshot.page_count is None
    assert len(snapshot.warnings) == 1
    assert "read-only render workdir" in snapshot.warnings[0]


def test_docx_render_invalid_converted_pdf_keeps_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_docx(
        tmp_path / "sample.docx",
        heading="Q2 Results",
        paragraphs=["Revenue increased."],
        rows=[["Region", "Total"]],
    )
    converted = tmp_path / "sample.pdf"
    converted.write_bytes(b"not a PDF")
    monkeypatch.setattr(docx_module, "find_libreoffice", lambda: tmp_path / "soffice")
    monkeypatch.setattr(
        docx_module,
        "convert_docx_to_pdf",
        lambda source, output_dir, executable: converted,
    )

    snapshot = DocxAdapter().load(source, render=True, workdir=tmp_path / "work")

    assert snapshot.blocks[0].text == "Q2 Results"
    assert snapshot.pages == []
    assert len(snapshot.warnings) == 1
    assert "invalid PDF" in snapshot.warnings[0]
