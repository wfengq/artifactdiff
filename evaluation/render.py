"""Render paragraph lists to byte-stable DOCX and text-layer PDF files."""

from __future__ import annotations

import zipfile
from collections.abc import Sequence
from datetime import datetime
from io import BytesIO
from pathlib import Path

from docx import Document
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen.canvas import Canvas

from evaluation.models import Format, Language

_FIXED_TIME = datetime(2000, 1, 1, 0, 0, 0)
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MARGIN = 54.0
_FONT_SIZE = 10.0
_LEADING = 14.0
_ZH_FONT = "STSong-Light"
_TYPOGRAPHY = str.maketrans(
    {
        "“": '"',
        "”": '"',
        "„": '"',
        "‘": "'",
        "’": "'",
        "‚": "'",
        "–": "-",
        "—": "-",
        "…": "...",
        " ": " ",
    }
)


def latin1_safe(text: str) -> tuple[str, int]:
    """Map common typography to ASCII, then replace other non-Latin-1 characters."""
    mapped = text.translate(_TYPOGRAPHY)
    replaced = 0
    characters: list[str] = []
    for character in mapped:
        if ord(character) > 0xFF:
            characters.append("?")
            replaced += 1
        else:
            characters.append(character)
    return "".join(characters), replaced


def render_docx(paragraphs: Sequence[str], path: Path) -> Path:
    document = Document()
    properties = document.core_properties
    properties.author = "ArtifactDiff evaluation"
    properties.last_modified_by = "ArtifactDiff evaluation"
    properties.created = _FIXED_TIME
    properties.modified = _FIXED_TIME
    properties.revision = 1
    for paragraph in paragraphs:
        document.add_paragraph(paragraph)
    buffer = BytesIO()
    document.save(buffer)
    path.write_bytes(_stable_zip(buffer.getvalue()))
    return path


def render_pdf(paragraphs: Sequence[str], path: Path, *, language: Language) -> int:
    """Write a wrapped, deterministic PDF and return the replaced-character count."""
    replaced = 0
    if language == "zh":
        _register_zh_font()
        font = _ZH_FONT
        lines_by_paragraph = [_wrap_characters(text, font) for text in paragraphs]
    else:
        font = "Helvetica"
        safe: list[str] = []
        for text in paragraphs:
            cleaned, count = latin1_safe(text)
            safe.append(cleaned)
            replaced += count
        lines_by_paragraph = [_wrap_words(text, font) for text in safe]

    canvas = Canvas(str(path), pagesize=A4, invariant=1, pageCompression=1)
    canvas.setAuthor("ArtifactDiff evaluation")
    canvas.setTitle("ArtifactDiff evaluation contract")
    _, height = A4
    y = height - _MARGIN
    canvas.setFont(font, _FONT_SIZE)
    for lines in lines_by_paragraph:
        for line in lines:
            if y < _MARGIN:
                canvas.showPage()
                canvas.setFont(font, _FONT_SIZE)
                y = height - _MARGIN
            canvas.drawString(_MARGIN, y, line)
            y -= _LEADING
        y -= _LEADING
    canvas.save()
    return replaced


def render(paragraphs: Sequence[str], path: Path, *, fmt: Format, language: Language) -> int:
    if fmt is Format.DOCX:
        render_docx(paragraphs, path)
        return 0
    return render_pdf(paragraphs, path, language=language)


def _usable_width() -> float:
    width, _ = A4
    return float(width) - 2 * _MARGIN


def _wrap_words(text: str, font: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}" if current else word
        if current and pdfmetrics.stringWidth(candidate, font, _FONT_SIZE) > _usable_width():
            lines.append(current)
            current = word
        else:
            current = candidate
    return [*lines, current] if current else lines or [""]


def _wrap_characters(text: str, font: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for character in text:
        candidate = current + character
        if current and pdfmetrics.stringWidth(candidate, font, _FONT_SIZE) > _usable_width():
            lines.append(current)
            current = character
        else:
            current = candidate
    return [*lines, current] if current else lines or [""]


def _register_zh_font() -> None:
    if _ZH_FONT not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont(_ZH_FONT))


def _stable_zip(package: bytes) -> bytes:
    output = BytesIO()
    with (
        zipfile.ZipFile(BytesIO(package)) as source,
        zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target,
    ):
        for name in sorted(source.namelist()):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            target.writestr(info, source.read(name))
    return output.getvalue()
