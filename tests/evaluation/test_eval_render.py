import re
from pathlib import Path

import pdfplumber

from artifactdiff import inspect_contract
from evaluation.render import latin1_safe, render_docx, render_pdf

EN = (
    "Article I Parties",
    "Acme Inc. and Beta Ltd. enter this agreement.",
    "Article II Payment Terms",
    "The Customer shall pay within 30 days of invoice. Late amounts accrue 5% interest.",
)
ZH = (
    "第一条 合同主体",
    "甲方：上海示例科技有限公司；乙方：北京样例贸易有限公司。",
    "第二条 付款条件",
    "甲方应于2026年8月4日后30天内支付人民币10,000元。乙方不得迟延交付。",
)


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _clause_text(path: Path) -> str:
    payload = inspect_contract(path, max_clauses=1000)
    clauses = payload["clauses"]
    assert isinstance(clauses, list)
    return _squash("".join(str(clause["text"]) for clause in clauses))


def test_docx_render_is_byte_stable(tmp_path: Path) -> None:
    first = render_docx(EN, tmp_path / "a.docx")
    second = render_docx(EN, tmp_path / "b.docx")
    assert first.read_bytes() == second.read_bytes()


def test_pdf_render_is_byte_stable_for_en_and_zh(tmp_path: Path) -> None:
    for language, paragraphs in (("en", EN), ("zh", ZH)):
        render_pdf(paragraphs, tmp_path / f"{language}-a.pdf", language=language)
        render_pdf(paragraphs, tmp_path / f"{language}-b.pdf", language=language)
        assert (tmp_path / f"{language}-a.pdf").read_bytes() == (
            tmp_path / f"{language}-b.pdf"
        ).read_bytes()


def test_pdf_text_layer_round_trips_through_artifactdiff(tmp_path: Path) -> None:
    for language, paragraphs in (("en", EN), ("zh", ZH)):
        path = tmp_path / f"{language}.pdf"
        assert render_pdf(paragraphs, path, language=language) == 0
        text = _clause_text(path)
        for paragraph in paragraphs:
            assert _squash(paragraph) in text
    labels = [
        clause["label"]["normalized"]
        for clause in inspect_contract(tmp_path / "zh.pdf")["clauses"]  # type: ignore[union-attr]
    ]
    assert "第二条" in labels


def test_docx_text_round_trips_through_artifactdiff(tmp_path: Path) -> None:
    path = render_docx(ZH, tmp_path / "zh.docx")
    text = _clause_text(path)
    assert all(_squash(paragraph) in text for paragraph in ZH)


def test_long_paragraphs_wrap_across_pages(tmp_path: Path) -> None:
    paragraphs = tuple(
        f"Clause {index} " + " ".join(f"word{index}x{n}" for n in range(60))
        for index in range(200)
    )
    path = tmp_path / "long.pdf"
    render_pdf(paragraphs, path, language="en")
    with pdfplumber.open(path) as pdf:
        assert len(pdf.pages) > 1
    text = _clause_text(path)
    assert _squash(paragraphs[0]) in text and _squash(paragraphs[-1]) in text


def test_latin1_safe_maps_typography_then_counts_replacements() -> None:
    assert latin1_safe("“Agreement” – café … 中") == ('"Agreement" - café ... ?', 1)


def test_english_pdf_reports_replaced_characters(tmp_path: Path) -> None:
    assert render_pdf(("Price in 円 and ₩.",), tmp_path / "x.pdf", language="en") == 2
