"""Anchored clause-number parsing for supported contract formats."""

import re
from collections.abc import Callable
from re import Match, Pattern

from artifactdiff.contract.models import ClauseLabel
from artifactdiff.models import StrictModel
from artifactdiff.normalize import normalize_text


class ClauseMarker(StrictModel):
    """A parsed clause label, its nesting level, and the following heading."""

    level: int
    label: ClauseLabel
    heading: str


PATTERNS: tuple[tuple[str, Pattern[str], Callable[[Match[str]], int]], ...] = (
    (
        "chinese_article",
        re.compile(r"^(\u7b2c\s*[\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341\u767e\u5343\u96f6\u3007\u4e240-9]+\s*\u6761)\s*(.*)$"),
        lambda _: 1,
    ),
    (
        "section",
        re.compile(r"^(\u7b2c\s*(\d+(?:\.\d+)*)\s*\u8282)\s*(.*)$"),
        lambda match: match.group(2).count(".") + 1,
    ),
    (
        "article",
        re.compile(r"^(Article\s+[IVXLCDM0-9]+)\b[.\uff1a:]?\s*(.*)$", re.I),
        lambda _: 1,
    ),
    (
        "section",
        re.compile(r"^(Section\s+(\d+(?:\.\d+)*))\b[.\uff1a:]?\s*(.*)$", re.I),
        lambda match: match.group(2).count(".") + 1,
    ),
    (
        "decimal",
        re.compile(r"^(\d+(?:\.\d+)+)[.\u3001\uff1a:]?\s*(.*)$"),
        lambda match: match.group(1).count(".") + 1,
    ),
    (
        "chinese_list",
        re.compile(r"^([\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341\u767e\u5343]+\u3001)\s*(.*)$"),
        lambda _: 2,
    ),
    (
        "chinese_list",
        re.compile(r"^\uff08([\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341\u767e\u5343]+)\uff09\s*(.*)$"),
        lambda _: 3,
    ),
)


def parse_clause_marker(text: str) -> ClauseMarker | None:
    """Parse a supported marker only when it starts the first text line."""
    first_line = text.replace("\u3000", " ").splitlines()[0] if text else ""
    for scheme, pattern, level_for in PATTERNS:
        match = pattern.match(first_line)
        if match is None:
            continue
        printed = match.group(1)
        if scheme == "chinese_list" and first_line.startswith("\uff08"):
            printed = f"\uff08{printed}\uff09"
        return ClauseMarker(
            level=level_for(match),
            label=ClauseLabel(
                printed=printed,
                normalized=normalize_text(printed),
                scheme=scheme,  # type: ignore[arg-type]
            ),
            heading=match.groups()[-1].strip(),
        )
    return None
