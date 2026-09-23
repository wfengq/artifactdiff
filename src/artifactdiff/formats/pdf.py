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

from artifactdiff.contract.features import FeatureInspectionError, inspect_pdf_features
from artifactdiff.errors import InputValidationError, ResourceLimitError
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, PageSnapshot, Rect
from artifactdiff.normalize import fingerprint, normalize_text

MAX_PAGES = 500
RENDER_SCALE = 2.0
_MIN_TWO_COLUMN_ROWS = 8
_MIN_TWO_COLUMN_ROW_RATIO = 0.6
_MIN_COLUMN_GUTTER_RATIO = 0.025

_PdfWord = dict[str, Any]
_PdfLine = tuple[str, float, float, float, float]


def _has_trailing_fill_line(
    strokes: list[dict[str, Any]], text_right: float, text_bottom: float
) -> bool:
    return any(
        abs(float(stroke["top"]) - float(stroke["bottom"])) <= 1
        and -3 <= float(stroke["x0"]) - text_right <= 12
        and float(stroke["x1"]) - float(stroke["x0"]) >= 48
        and abs(float(stroke["top"]) - text_bottom) <= 4
        for stroke in strokes
    )


def _group_rows(words: Iterable[_PdfWord]) -> list[list[_PdfWord]]:
    ordered = sorted(
        words,
        key=lambda word: (float(word["top"]), float(word["x0"]), str(word["text"])),
    )
    rows: list[list[_PdfWord]] = []
    for word in ordered:
        if not rows or float(word["top"]) - float(rows[-1][0]["top"]) > 3:
            rows.append([word])
        else:
            rows[-1].append(word)
    return rows


def _line(words: list[_PdfWord]) -> _PdfLine:
    ordered = sorted(
        words,
        key=lambda word: (float(word["x0"]), float(word["top"]), str(word["text"])),
    )
    return (
        " ".join(str(word["text"]) for word in ordered),
        min(float(word["x0"]) for word in ordered),
        min(float(word["top"]) for word in ordered),
        max(float(word["x1"]) for word in ordered),
        max(float(word["bottom"]) for word in ordered),
    )


def _has_two_columns(rows: list[list[_PdfWord]], page_width: float) -> bool:
    if len(rows) < _MIN_TWO_COLUMN_ROWS:
        return False
    midpoint = page_width / 2
    minimum_gutter = page_width * _MIN_COLUMN_GUTTER_RATIO
    separated_rows = 0
    for row in rows:
        left_edges = [float(word["x1"]) for word in row if float(word["x1"]) <= midpoint]
        right_edges = [float(word["x0"]) for word in row if float(word["x0"]) >= midpoint]
        if left_edges and right_edges and min(right_edges) - max(left_edges) >= minimum_gutter:
            separated_rows += 1
    return (
        separated_rows >= _MIN_TWO_COLUMN_ROWS
        and separated_rows / len(rows) >= _MIN_TWO_COLUMN_ROW_RATIO
    )


def _column_ordered_lines(rows: list[list[_PdfWord]], page_width: float) -> list[_PdfLine]:
    midpoint = page_width / 2
    lines: list[_PdfLine] = []
    left_rows: list[list[_PdfWord]] = []
    right_rows: list[list[_PdfWord]] = []

    def flush_columns() -> None:
        lines.extend(_line(row) for row in left_rows)
        lines.extend(_line(row) for row in right_rows)
        left_rows.clear()
        right_rows.clear()

    for row in rows:
        if any(float(word["x0"]) < midpoint < float(word["x1"]) for word in row):
            flush_columns()
            lines.append(_line(row))
            continue
        left = [word for word in row if float(word["x1"]) <= midpoint]
        right = [word for word in row if float(word["x0"]) >= midpoint]
        if left:
            left_rows.append(left)
        if right:
            right_rows.append(right)
    flush_columns()
    return lines


class _CloseStack:
    def __init__(self) -> None:
        self._resources: list[Any] = []

    def __enter__(self) -> '_CloseStack':
        return self

    def own(self, resource: Any) -> Any:
        self._resources.append(resource)
        return resource

    def __exit__(
        self, _error_type: object, error: BaseException | None, _traceback: object
    ) -> None:
        cleanup_error: BaseException | None = None
        for resource in reversed(self._resources):
            try:
                resource.close()
            except BaseException as close_error:
                if cleanup_error is None:
                    cleanup_error = close_error
        if error is None and cleanup_error is not None:
            raise cleanup_error


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
                features = inspect_pdf_features(document)
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
        except FeatureInspectionError as error:
            raise InputValidationError(f"invalid PDF: {path}") from error

        if render:
            self._render_pages(path, pages, workdir)
        blocks = [block for page in pages for block in page.blocks]
        return DocumentSnapshot.from_path(
            path,
            pages=pages,
            blocks=blocks,
            metadata={
                "document_features": [feature.model_dump(mode="json") for feature in features]
            },
        )

    def _extract_page(self, page: Any, page_index: int) -> PageSnapshot:
        words = page.extract_words(use_text_flow=True, keep_blank_chars=False) or []
        lines = self._lines(words, float(page.width))
        horizontal_strokes = [
            stroke
            for stroke in (getattr(page, "lines", None) or [])
            if float(stroke["x1"]) > float(stroke["x0"])
        ]
        blocks = [
            ContentBlock(
                id=f"pdf:{page_index}:{ordinal}:{fingerprint(text)}",
                ordinal=ordinal,
                page_index=page_index,
                content_type=ContentType.PDF_TEXT,
                text=text,
                normalized_text=normalize_text(text),
                bbox=Rect(x0=x0, y0=top, x1=x1, y1=bottom),
                metadata={"trailing_fill_line": True}
                if _has_trailing_fill_line(horizontal_strokes, x1, bottom)
                else {},
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
    def _lines(words: Iterable[_PdfWord], page_width: float) -> list[_PdfLine]:
        rows = _group_rows(words)
        if _has_two_columns(rows, page_width):
            return _column_ordered_lines(rows, page_width)
        return [_line(row) for row in rows]

    @staticmethod
    def _render_pages(path: Path, pages: list[PageSnapshot], workdir: Path) -> None:
        output_dir = workdir / "pages"
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            document = pdfium.PdfDocument(str(path))
            with _CloseStack() as document_resources:
                document_resources.own(document)
                for snapshot in pages:
                    with _CloseStack() as page_resources:
                        page = page_resources.own(document[snapshot.index])
                        bitmap = page_resources.own(page.render(scale=RENDER_SCALE))
                        source_image = page_resources.own(bitmap.to_pil())
                        image = source_image.convert('RGB')
                        if image is not source_image:
                            page_resources.own(image)
                        output_path = output_dir / f'page-{snapshot.index + 1:04d}.png'
                        image.save(output_path)
                        snapshot.render_path = str(output_path)
        except pdfium.PdfiumError as error:
            raise InputValidationError(f"invalid PDF: {path}") from error
