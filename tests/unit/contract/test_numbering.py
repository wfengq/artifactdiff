import pytest

from artifactdiff.contract.numbering import parse_clause_marker


@pytest.mark.parametrize(
    ("text", "scheme", "level", "printed"),
    [
        ("\u7b2c\u56db\u6761 \u4ed8\u6b3e\u6761\u4ef6", "chinese_article", 1, "\u7b2c\u56db\u6761"),
        ("\u7b2c 4 \u6761 \u4ed8\u6b3e\u6761\u4ef6", "chinese_article", 1, "\u7b2c 4 \u6761"),
        ("\u4e00\u3001\u4ed8\u6b3e\u6761\u4ef6", "chinese_list", 2, "\u4e00\u3001"),
        ("\uff08\u4e00\uff09\u4ed8\u6b3e\u65f6\u95f4", "chinese_list", 3, "\uff08\u4e00\uff09"),
        ("4.2 Payment timing", "decimal", 2, "4.2"),
        ("Article IV Payment Terms", "article", 1, "Article IV"),
        ("Section 4.2 Payment timing", "section", 2, "Section 4.2"),
    ],
)
def test_parse_clause_marker(
    text: str, scheme: str, level: int, printed: str
) -> None:
    marker = parse_clause_marker(text)

    assert marker is not None
    assert (marker.label.scheme, marker.level, marker.label.printed) == (
        scheme,
        level,
        printed,
    )


def test_parse_clause_marker_requires_marker_at_start_of_line() -> None:
    assert parse_clause_marker("Payment terms: Section 4.2") is None
