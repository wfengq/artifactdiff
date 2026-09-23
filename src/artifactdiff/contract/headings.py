"""Extract displayed contract headings without changing the clause IR.

A numbered line may start a useful clause for comparison while still being
ordinary body text. This view is deliberately narrower than the clause tree.
"""

import re

from artifactdiff.contract.analyzer import visible_contract_blocks
from artifactdiff.contract.models import ContractClause, ContractDocument
from artifactdiff.contract.numbering import parse_clause_marker
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot

_CHAPTER = re.compile(r"^(第\s*[一二三四五六七八九十百千零〇两0-9]+\s*章)\s*(\S.*)$")
_CHINESE_LIST = re.compile(r"^([一二三四五六七八九十百千]+、)\s*(\S.*)$")
_ANNEX_START = re.compile(r"^(?:附件|附录)\s*(?:[A-Za-z0-9一二三四五六七八九十百千]+)?$")
_CONTRACT_TITLE = re.compile(r"^.{1,30}(?:合同书?|协议书?)$")
_USAGE_NOTE_TITLES = frozenset({"使用说明", "填写说明"})
_SPACED_HAN = re.compile(r"(?:[\u4e00-\u9fff]\s+){3}")
_CJK_GAP = re.compile(r"(?<=[\u4e00-\u9fff、，。])\s+(?=[\u4e00-\u9fff、，。])")
_SENTENCE_PUNCTUATION = frozenset("。！？；;：:")
_PDF_TITLE_RIGHT_EDGE = 0.74


def _body_start_after_usage_notes(snapshot: DocumentSnapshot, blocks: list[ContentBlock]) -> int:
    if snapshot.format != "pdf":
        return 0
    for index, block in enumerate(blocks):
        if block.text.strip() not in _USAGE_NOTE_TITLES:
            continue
        cover_titles = {
            previous.text.strip()
            for previous in blocks[:index]
            if _CONTRACT_TITLE.fullmatch(previous.text.strip())
        }
        for body_index in range(index + 1, len(blocks)):
            body_text = blocks[body_index].text.strip()
            marker = parse_clause_marker(body_text)
            if marker is not None and marker.label.scheme != "chinese_list":
                return 0
            if body_text in cover_titles:
                return body_index
        break
    return 0


def _after_label(text: str) -> str:
    return text.lstrip(" \u3000:：")


def _title_like(text: str, block: ContentBlock, snapshot: DocumentSnapshot) -> bool:
    if block.metadata.get("trailing_fill_line") is True:
        return False
    if block.content_type is ContentType.HEADING:
        return bool(text)
    if not text or any(mark in text for mark in _SENTENCE_PUNCTUATION):
        return False
    if snapshot.format != "pdf" or block.bbox is None or block.page_index is None:
        return len(text) <= 32
    if block.page_index >= len(snapshot.pages):
        return False
    page = snapshot.pages[block.page_index]
    if block.bbox.x0 < page.width / 2:
        return block.bbox.x1 <= page.width * _PDF_TITLE_RIGHT_EDGE
    text_width = block.bbox.x1 - block.bbox.x0
    available_width = page.width - block.bbox.x0
    return text_width <= available_width * _PDF_TITLE_RIGHT_EDGE


def _clause_heading(
    clause: ContractClause,
    block: ContentBlock,
    snapshot: DocumentSnapshot,
    accepted_ids: set[str],
) -> str | None:
    title = _after_label(clause.heading)
    if not _title_like(title, block, snapshot):
        return None
    if block.content_type is ContentType.HEADING:
        return " ".join(part for part in (clause.label.printed, title) if part)
    if not clause.label.printed:
        return None
    if clause.parent_id is not None and clause.parent_id not in accepted_ids:
        return None
    return " ".join(part for part in (clause.label.printed, title) if part)


def extract_independent_headings(
    snapshot: DocumentSnapshot, contract: ContractDocument
) -> list[str]:
    """Return headings visibly separate from body text, in source order.

    The underlying clauses, identifiers, hierarchy, and selectors are unchanged.
    PDF decisions use line geometry; DOCX heading styles are direct evidence.
    """
    clauses_by_start = {
        clause.evidence[0].block_id: clause
        for clause in contract.clauses
        if clause.evidence and clause.heading
    }
    accepted_ids: set[str] = set()
    headings: list[str] = []
    seen: set[str] = set()
    blocks = visible_contract_blocks(snapshot)
    body_start = _body_start_after_usage_notes(snapshot, blocks)
    for index, block in enumerate(blocks):
        if index < body_start:
            continue
        if block.content_type in {ContentType.HEADER, ContentType.FOOTER}:
            continue
        text = block.text.strip()
        spaced_han = _SPACED_HAN.search(text) is not None
        if spaced_han:
            text = _CJK_GAP.sub("", text)
        if headings and _ANNEX_START.fullmatch(text):
            break
        clause = clauses_by_start.get(block.id)
        chapter = _CHAPTER.match(text)
        if chapter is not None and _title_like(_after_label(chapter.group(2)), block, snapshot):
            heading = f"{chapter.group(1)} {_after_label(chapter.group(2))}"
            if heading not in seen:
                headings.append(heading)
                seen.add(heading)
            continue
        chinese_list = _CHINESE_LIST.match(text)
        if chinese_list is not None and _title_like(_after_label(chinese_list.group(2)), block, snapshot):
            heading = f"{chinese_list.group(1)} {_after_label(chinese_list.group(2))}"
            if heading not in seen:
                headings.append(heading)
                seen.add(heading)
            if clause is not None:
                accepted_ids.add(clause.id)
            continue
        if clause is None:
            next_block = blocks[index + 1] if index + 1 < len(blocks) else None
            next_clause = clauses_by_start.get(next_block.id) if next_block is not None else None
            followed_by_numbered_heading = (
                next_block is not None
                and next_block.page_index == block.page_index
                and next_clause is not None
                and bool(next_clause.label.printed)
            )
            if (
                spaced_han
                and followed_by_numbered_heading
                and _title_like(text, block, snapshot)
                and text not in seen
            ):
                headings.append(text)
                seen.add(text)
            continue
        clause_heading = _clause_heading(clause, block, snapshot, accepted_ids)
        if clause_heading is not None:
            if clause_heading not in seen:
                headings.append(clause_heading)
                seen.add(clause_heading)
            accepted_ids.add(clause.id)
    return headings
