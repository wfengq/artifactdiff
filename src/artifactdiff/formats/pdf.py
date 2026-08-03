"""PDF snapshot extraction and page rendering."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pdfplumber
import pypdfium2 as pdfium
from pdfminer.pdfdocument import PDFPasswordIncorrect
from pdfminer.pdfparser import PDFSyntaxError
from pdfplumber.utils.exceptions import PdfminerException

from artifactdiff.errors import InputValidationError, ResourceLimitError
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, PageSnapshot, Rect
from artifactdiff.normalize import fingerprint, normalize_text

MAX_PAGES = 500
RENDER_SCALE = 2.0


class PdfAdapter:
    """Create snapshots from PDF text geometry and optional rendered pages."""

    def load(
        self, path: Path, *, render: bool, workdir: Path, force: bool = False
    ) -> DocumentSnapshot:
        """Extract PDF pages and render them at 144 DPI when requested."""
        try:
            with pdfplumber.open(path) as document:
                if not force and len(document.pages) > MAX_PAGES:
                    raise ResourceLimitError(f"Document exceeds the 500 page limit: {path}")
                pages = [
                    self._extract_page(page, index) for index, page in enumerate(document.pages)
                ]
        except ResourceLimitError:
            raise
        except PdfminerException as error:
            detail = error.args[0] if error.args else None
            if isinstance(detail, PDFPasswordIncorrect):
                raise InputValidationError(f'encrypted PDF: {path}') from error
            raise InputValidationError(f'invalid PDF: {path}') from error
        except PDFPasswordIncorrect as error:
            raise InputValidationError(f"encrypted PDF: {path}") from error
        except PDFSyntaxError as error:
            raise InputValidationError(f"invalid PDF: {path}") from error
        except OSError as error:
            raise InputValidationError(f"invalid PDF: {path}") from error

        if render:
            self._render_pages(path, pages, workdir)
        blocks = [block for page in pages for block in page.blocks]
        return DocumentSnapshot.from_path(path, pages=pages, blocks=blocks)

    def _extract_page(self, page: Any, page_index: int) -> PageSnapshot:
        words = page.extract_words(use_text_flow=True, keep_blank_chars=False) or []
        lines = self._lines(words)
        blocks = [
            ContentBlock(
                id=f"pdf:{page_index}:{ordinal}:{fingerprint(text)}",
                ordinal=ordinal,
                page_index=page_index,
                content_type=ContentType.PDF_TEXT,
                text=text,
                normalized_text=normalize_text(text),
                bbox=Rect(x0=x0, y0=top, x1=x1, y1=bottom),
            )
            for ordinal, (text, x0, top, x1, bottom) in enumerate(lines)
        ]
        text = "\n".join(block.text for block in blocks)
        return PageSnapshot(
            index=page_index,
            width=float(page.width),
            height=float(page.height),
            text=text,
            normalized_text=normalize_text(text),
            blocks=blocks,
        )

    @staticmethod
    def _lines(words: Iterable[dict[str, Any]]) -> list[tuple[str, float, float, float, float]]:
        ordered = sorted(
            words,
            key=lambda word: (float(word["top"]), float(word["x0"]), str(word["text"])),
        )
        grouped: list[list[dict[str, Any]]] = []
        for word in ordered:
            if not grouped or float(word["top"]) - float(grouped[-1][0]["top"]) > 3:
                grouped.append([word])
            else:
                grouped[-1].append(word)

        lines: list[tuple[str, float, float, float, float]] = []
        for line in grouped:
            line.sort(key=lambda word: (float(word["x0"]), float(word["top"]), str(word["text"])))
            lines.append(
                (
                    " ".join(str(word["text"]) for word in line),
                    min(float(word["x0"]) for word in line),
                    min(float(word["top"]) for word in line),
                    max(float(word["x1"]) for word in line),
                    max(float(word["bottom"]) for word in line),
                )
            )
        return lines

    @staticmethod
    def _render_pages(path: Path, pages: list[PageSnapshot], workdir: Path) -> None:
        output_dir = workdir / "pages"
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            document = pdfium.PdfDocument(str(path))
            try:
                for snapshot in pages:
                    page = document[snapshot.index]
                    try:
                        bitmap = page.render(scale=RENDER_SCALE)
                        try:
                            source_image = bitmap.to_pil()
                            try:
                                image = source_image.convert('RGB')
                                try:
                                    output_path = (
                                        output_dir / f'page-{snapshot.index + 1:04d}.png'
                                    )
                                    image.save(output_path)
                                    snapshot.render_path = str(output_path)
                                finally:
                                    if image is not source_image:
                                        image.close()
                            finally:
                                source_image.close()
                        finally:
                            bitmap.close()
                    finally:
                        page.close()
            finally:
                document.close()
        except pdfium.PdfiumError as error:
            raise InputValidationError(f"invalid PDF: {path}") from error
