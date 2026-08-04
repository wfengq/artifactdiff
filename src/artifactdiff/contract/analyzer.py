"""Single-pass deterministic construction of contract intermediate representation."""

import hashlib
from dataclasses import dataclass, field

from artifactdiff.contract.entities import extract_entities
from artifactdiff.contract.language import detect_language
from artifactdiff.contract.models import (
    ClauseLabel,
    ContractClause,
    ContractDocument,
    EvidenceRef,
    ProtectedRegion,
    ProtectedRegionKind,
)
from artifactdiff.contract.numbering import ClauseMarker, parse_clause_marker
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, SourceDescriptor
from artifactdiff.normalize import fingerprint, normalize_text

SIGNATURE_TERMS = frozenset({"\u7b7e\u5b57", "\u7b7e\u540d", "\u6388\u6743\u4ee3\u8868", "signature", "signed by"})
SEAL_TERMS = frozenset({"\u76d6\u7ae0", "\u516c\u7ae0", "\u5370\u7ae0", "seal", "company chop"})
ATTACHMENT_TERMS = frozenset({"\u9644\u4ef6", "\u9644\u5f55", "appendix", "attachment", "schedule"})


@dataclass
class _ClauseDraft:
    label: ClauseLabel
    heading: str
    ancestor_path: tuple[str, ...]
    level: int | None
    parent_index: int | None
    blocks: list[ContentBlock] = field(default_factory=list)


def _evidence(block: ContentBlock) -> EvidenceRef:
    return EvidenceRef(block_id=block.id, page_index=block.page_index, bbox=block.bbox)


def _clause_id(draft: _ClauseDraft) -> str:
    text = "\n".join(block.text for block in draft.blocks)
    material = "\0".join(
        (
            draft.label.normalized,
            *draft.ancestor_path,
            normalize_text(draft.heading),
            normalize_text(text)[:160],
        )
    ).encode("utf-8")
    return f"clause-{hashlib.sha256(material).hexdigest()[:24]}"


def _region_kind(block: ContentBlock) -> ProtectedRegionKind | None:
    if block.content_type is ContentType.HEADER:
        return ProtectedRegionKind.HEADER
    if block.content_type is ContentType.FOOTER:
        return ProtectedRegionKind.FOOTER
    normalized = normalize_text(block.text)
    for kind, terms in (
        (ProtectedRegionKind.SIGNATURE, SIGNATURE_TERMS),
        (ProtectedRegionKind.SEAL, SEAL_TERMS),
        (ProtectedRegionKind.ATTACHMENT, ATTACHMENT_TERMS),
    ):
        if normalized.startswith(tuple(terms)):
            return kind
    return None


def _protected_region(block: ContentBlock, kind: ProtectedRegionKind) -> ProtectedRegion:
    text_fingerprint = fingerprint(block.text)
    material = f"{kind.value}\0{text_fingerprint}\0{block.id}".encode("utf-8")
    return ProtectedRegion(
        id=f"region-{hashlib.sha256(material).hexdigest()[:24]}",
        kind=kind,
        text_fingerprint=text_fingerprint,
        evidence=[_evidence(block)],
    )


def _marker_for(block: ContentBlock) -> ClauseMarker | None:
    return parse_clause_marker(block.text)


def analyze_contract(snapshot: DocumentSnapshot) -> ContractDocument:
    """Analyze one snapshot into stable clauses, entities, tables, and protected regions."""
    drafts: list[_ClauseDraft] = []
    stack: list[int] = []
    active_index: int | None = None
    tables: list[EvidenceRef] = []
    protected_regions: list[ProtectedRegion] = []

    for block in sorted(snapshot.blocks, key=lambda item: item.ordinal):
        region_kind = _region_kind(block)
        if region_kind is not None:
            protected_regions.append(_protected_region(block, region_kind))
        if block.content_type is ContentType.TABLE:
            tables.append(_evidence(block))
        if block.content_type in {ContentType.HEADER, ContentType.FOOTER}:
            continue

        marker = _marker_for(block)
        starts_clause = block.content_type is ContentType.HEADING or marker is not None
        if starts_clause:
            if marker is None:
                marker = ClauseMarker(
                    level=1,
                    label=ClauseLabel(printed="", normalized="", scheme="none"),
                    heading=block.text.splitlines()[0].strip() if block.text else "",
                )
            while stack and (drafts[stack[-1]].level or 0) >= marker.level:
                stack.pop()
            parent_index = stack[-1] if stack else None
            ancestor_path = (
                drafts[parent_index].ancestor_path + (drafts[parent_index].heading,)
                if parent_index is not None
                else ()
            )
            drafts.append(
                _ClauseDraft(
                    label=marker.label,
                    heading=marker.heading,
                    ancestor_path=ancestor_path,
                    level=marker.level,
                    parent_index=parent_index,
                    blocks=[block],
                )
            )
            active_index = len(drafts) - 1
            stack.append(active_index)
        elif active_index is not None:
            drafts[active_index].blocks.append(block)
        elif normalize_text(block.text):
            drafts.append(
                _ClauseDraft(
                    label=ClauseLabel(printed="", normalized="", scheme="none"),
                    heading="",
                    ancestor_path=(),
                    level=None,
                    parent_index=None,
                    blocks=[block],
                )
            )
            active_index = len(drafts) - 1

    ids = [_clause_id(draft) for draft in drafts]
    clauses: list[ContractClause] = []
    all_entities = []
    for index, draft in enumerate(drafts):
        text = "\n".join(block.text for block in draft.blocks)
        clause_entities = [
            entity
            for block in draft.blocks
            for entity in extract_entities(block.text, ids[index], _evidence(block))
        ]
        all_entities.extend(clause_entities)
        children = [ids[child] for child, item in enumerate(drafts) if item.parent_index == index]
        clauses.append(
            ContractClause(
                id=ids[index],
                label=draft.label,
                heading=draft.heading,
                ancestor_path=draft.ancestor_path,
                text=text,
                normalized_text=normalize_text(text),
                fingerprint=fingerprint(text),
                parent_id=ids[draft.parent_index] if draft.parent_index is not None else None,
                child_ids=children,
                evidence=[_evidence(block) for block in draft.blocks],
                entities=clause_entities,
            )
        )

    source = SourceDescriptor(
        path=snapshot.source_path,
        sha256=snapshot.sha256,
        format=snapshot.format,
        size_bytes=snapshot.size_bytes,
    )
    return ContractDocument(
        source=source,
        language=detect_language("\n".join(block.text for block in snapshot.blocks)),
        clauses=clauses,
        tables=tables,
        protected_regions=protected_regions,
        entities=all_entities,
        warnings=list(snapshot.warnings),
    )
