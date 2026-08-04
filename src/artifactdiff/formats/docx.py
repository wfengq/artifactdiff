"""DOCX logical structure extraction with optional visual rendering."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from zipfile import BadZipFile

from docx import Document
from docx.document import Document as DocumentType
from docx.opc.exceptions import PackageNotFoundError
from docx.oxml.ns import qn
from docx.table import Table
from docx.text.paragraph import Paragraph
from lxml.etree import XMLSyntaxError

from artifactdiff.contract.features import FeatureInspectionError, inspect_docx_features
from artifactdiff.errors import ArtifactDiffError, InputValidationError, RenderUnavailableError
from artifactdiff.formats.pdf import PdfAdapter
from artifactdiff.libreoffice import convert_docx_to_pdf, find_libreoffice
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, PageSnapshot
from artifactdiff.normalize import fingerprint, normalize_text


def iter_body_items(document: DocumentType) -> Iterator[Paragraph | Table]:
    """Yield body paragraphs and tables in their original document order."""
    for child in document.element.body.iterchildren():
        if child.tag == qn("w:p"):
            yield Paragraph(child, document)
        elif child.tag == qn("w:tbl"):
            yield Table(child, document)


def _visible_paragraph_text(paragraph: Paragraph) -> str:
    pieces: list[str] = []

    def visit(node: Any) -> None:
        tag = getattr(node, "tag", "")
        if tag in {qn("w:ins"), qn("w:del")}:
            return
        if tag == qn("w:r"):
            properties = node.find(qn("w:rPr"))
            if properties is not None and any(
                properties.find(qn(f"w:{kind}")) is not None
                for kind in ("vanish", "webHidden")
            ):
                return
        if tag == qn("w:t") and node.text:
            pieces.append(str(node.text))
        elif tag == qn("w:tab"):
            pieces.append("\t")
        elif tag in {qn("w:br"), qn("w:cr")}:
            pieces.append("\n")
        for child in node:
            visit(child)

    visit(paragraph._p)
    return "".join(pieces)


class DocxAdapter:
    """Create a semantic snapshot from DOCX body structure."""

    def load(
        self, path: Path, *, render: bool, workdir: Path, force: bool = False
    ) -> DocumentSnapshot:
        """Extract ordered paragraphs and tables from a DOCX source."""
        try:
            document = Document(path)
        except (
            BadZipFile,
            KeyError,
            OSError,
            PackageNotFoundError,
            ValueError,
            XMLSyntaxError,
        ) as error:
            raise InputValidationError(f"invalid DOCX: {path}") from error
        blocks: list[ContentBlock] = []
        for item in iter_body_items(document):
            block = self._body_block(item, len(blocks))
            if block is not None:
                blocks.append(block)
        self._append_section_blocks(document, blocks)
        try:
            features = inspect_docx_features(path)
        except FeatureInspectionError as error:
            raise InputValidationError(f"invalid DOCX: {path}") from error
        warnings: list[str] = []
        pages: list[PageSnapshot] = []
        if render:
            executable = find_libreoffice()
            if executable is None:
                warnings.append("DOCX visual rendering unavailable: LibreOffice was not found")
            else:
                try:
                    converted = convert_docx_to_pdf(path, workdir / "libreoffice", executable)
                except RenderUnavailableError as error:
                    warnings.append(f"DOCX visual rendering unavailable: {error}")
                else:
                    try:
                        rendered = PdfAdapter().load(
                            converted,
                            render=True,
                            workdir=workdir / "pdf-render",
                            force=force,
                        )
                    except ArtifactDiffError as error:
                        warnings.append(f"DOCX visual rendering unavailable: {error}")
                    else:
                        pages = rendered.pages
        return DocumentSnapshot.from_path(
            path,
            pages=pages,
            blocks=blocks,
            warnings=warnings,
            metadata={
                "document_features": [feature.model_dump(mode="json") for feature in features]
            },
        )

    @staticmethod
    def _append_section_blocks(document: DocumentType, blocks: list[ContentBlock]) -> None:
        for content_type, part_name in (
            (ContentType.HEADER, "header"),
            (ContentType.FOOTER, "footer"),
        ):
            seen: set[str] = set()
            for section in document.sections:
                part = getattr(section, part_name)
                text = "\n".join(
                    paragraph.text.strip()
                    for paragraph in part.paragraphs
                    if paragraph.text.strip()
                )
                if not text or text in seen:
                    continue
                seen.add(text)
                ordinal = len(blocks)
                blocks.append(
                    ContentBlock(
                        id=f"docx:{ordinal}:{content_type}:{fingerprint(text)}",
                        ordinal=ordinal,
                        content_type=content_type,
                        text=text,
                        normalized_text=normalize_text(text),
                    )
                )

    @staticmethod
    def _body_block(item: Paragraph | Table, ordinal: int) -> ContentBlock | None:
        if isinstance(item, Paragraph):
            text = _visible_paragraph_text(item).strip()
            if not text:
                return None
            style_name = item.style.name if item.style is not None else ""
            metadata: dict[str, int] = {}
            content_type = ContentType.PARAGRAPH
            if style_name.startswith("Heading "):
                try:
                    metadata["level"] = int(style_name.removeprefix("Heading "))
                except ValueError:
                    pass
                else:
                    content_type = ContentType.HEADING
            else:
                for prefix, kind in (("List Bullet", "bullet"), ("List Number", "number")):
                    if not style_name.startswith(prefix):
                        continue
                    suffix = style_name.removeprefix(prefix).strip()
                    metadata = {
                        "list_kind": kind,
                        "level": int(suffix) if suffix.isdigit() else 1,
                    }
                    break
        else:
            rows = [
                [
                    "\n".join(_visible_paragraph_text(paragraph) for paragraph in cell.paragraphs)
                    for cell in row.cells
                ]
                for row in item.rows
            ]
            text = "\n".join("\t".join(cells) for cells in rows)
            if not text.strip():
                return None
            content_type = ContentType.TABLE
            metadata = {"rows": len(item.rows), "columns": len(item.columns)}

        return ContentBlock(
            id=f"docx:{ordinal}:{content_type}:{fingerprint(text)}",
            ordinal=ordinal,
            content_type=content_type,
            text=text,
            normalized_text=normalize_text(text),
            metadata=metadata,
        )
