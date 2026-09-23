"""Independent display headings are not the same as numbered IR clauses."""

from artifactdiff.contract.analyzer import analyze_contract
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, PageSnapshot, Rect
from artifactdiff.normalize import normalize_text


def _pdf_snapshot(*lines: tuple[str, float, float]) -> DocumentSnapshot:
    blocks = [
        ContentBlock(
            id=f"pdf:0:{index}",
            ordinal=index,
            page_index=0,
            content_type=ContentType.PDF_TEXT,
            text=text,
            normalized_text=normalize_text(text),
            bbox=Rect(x0=x0, y0=40 + index * 25, x1=x1, y1=55 + index * 25),
        )
        for index, (text, x0, x1) in enumerate(lines)
    ]
    return DocumentSnapshot(
        source_path="example.pdf",
        format="pdf",
        sha256="a" * 64,
        size_bytes=1,
        page_count=1,
        pages=[
            PageSnapshot(
                index=0,
                width=595,
                height=842,
                text="\n".join(block.text for block in blocks),
                normalized_text=normalize_text("\n".join(block.text for block in blocks)),
                blocks=blocks,
            )
        ],
        blocks=blocks,
    )


def test_pdf_display_headings_exclude_instructions_and_inline_clauses() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("一、本合同文本为示范文本，供双方签约前阅读和填写。", 105, 520),
        ("第一章 合同主体", 232, 362),
        ("第一条 物业服务区域基本情况", 122, 338),
        ("第二条 乙方应将相关信息在物业服务区域显著位置公示", 122, 505),
        ("（一）乙方应当及时通知甲方。", 122, 450),
        ("第三条 机动车停放费", 122, 290),
    )
    contract = analyze_contract(snapshot)

    assert extract_independent_headings(snapshot, contract) == [
        "第一章 合同主体",
        "第一条 物业服务区域基本情况",
        "第三条 机动车停放费",
    ]
    assert any(clause.label.printed == "第二条" for clause in contract.clauses)
    assert any(clause.label.printed == "（一）" for clause in contract.clauses)


def test_short_inline_sentence_is_not_a_display_heading() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("第一条 付款条件", 105, 230),
        ("第二条 甲方应付款。", 105, 260),
        ("第三条 乙方有权解除。", 105, 275),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == ["第一条 付款条件"]


def test_top_level_chinese_list_survives_wrong_ir_parent_and_spaced_pdf_glyphs() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("一、本合同供签约前阅读，应当仔细填写。", 105, 520),
        ("第一条 甲方应当履行本合同约定的义务。", 105, 505),
        ("一、劳动合同期限", 105, 226),
        ("第一条 乙方应当完成工作。", 105, 505),
        ("二、工作内容和工作地点", 105, 271),
        ("七 、 劳 动 合 同 的 变 更 、 解 除 、 终 止", 105, 331),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == [
        "一、 劳动合同期限",
        "二、 工作内容和工作地点",
        "七、 劳动合同的变更、解除、终止",
    ]


def test_spaced_pdf_title_without_clause_marker_is_heading() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("合 同 责 任", 138, 345),
        ("第一条 旅行社责任", 96, 204),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == [
        "合同责任",
        "第一条 旅行社责任",
    ]


def test_spaced_pdf_cover_label_is_not_a_contract_heading() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("示 范 文 本", 220, 375),
        ("本合同文本供签约前阅读。", 105, 490),
        ("第一条 付款条件", 105, 230),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == ["第一条 付款条件"]


def test_repeated_contents_heading_is_reported_once() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("第一条 服务内容", 105, 220),
        ("第一条 服务内容", 105, 220),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == ["第一条 服务内容"]


def test_annex_heading_sequence_is_not_reported_as_contract_body() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("一、合同标的", 105, 230),
        ("第十七条 合同附件", 105, 300),
        ("附件1", 105, 155),
        ("固定资产移交表", 210, 385),
        ("附件2", 105, 155),
        ("食堂考核办法", 210, 380),
        ("一、考核内容", 105, 210),
        ("二、考核细则", 105, 210),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == [
        "一、 合同标的",
        "第十七条 合同附件",
    ]


def test_preface_attachment_label_does_not_hide_later_contract_body() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    snapshot = _pdf_snapshot(
        ("附件1", 105, 155),
        ("第一条 服务内容", 105, 230),
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == ["第一条 服务内容"]


def test_docx_heading_style_is_evidence_even_without_number_or_with_colon() -> None:
    from artifactdiff.contract.headings import extract_independent_headings

    blocks = [
        ContentBlock(
            id="heading-1",
            ordinal=0,
            content_type=ContentType.HEADING,
            text="付款条件：",
            normalized_text=normalize_text("付款条件："),
        ),
        ContentBlock(
            id="paragraph-1",
            ordinal=1,
            content_type=ContentType.PARAGRAPH,
            text="第一条 甲方应付款。",
            normalized_text=normalize_text("第一条 甲方应付款。"),
        ),
    ]
    snapshot = DocumentSnapshot(
        source_path="example.docx",
        format="docx",
        sha256="a" * 64,
        size_bytes=1,
        blocks=blocks,
    )

    assert extract_independent_headings(snapshot, analyze_contract(snapshot)) == ["付款条件："]
