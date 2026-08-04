"""Single-pass deterministic construction of contract intermediate representation."""

import hashlib
from dataclasses import dataclass, field
from math import isfinite

from pydantic import ValidationError

from artifactdiff.contract.entities import extract_entities
from artifactdiff.contract.features import CONTRACT_VISIBLE_TEXT_METADATA_KEY
from artifactdiff.contract.language import detect_language
from artifactdiff.contract.models import (
    ClauseLabel,
    ContractClause,
    ContractDocument,
    DocumentFeature,
    DocumentFeatureKind,
    EvidenceRef,
    ProtectedRegion,
    ProtectedRegionKind,
)
from artifactdiff.contract.numbering import ClauseMarker, parse_clause_marker
from artifactdiff.models import ContentBlock, ContentType, DocumentSnapshot, Rect, SourceDescriptor
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
    rendered_page_index = block.metadata.get("rendered_page_index")
    rendered_bbox_data = block.metadata.get("rendered_bbox")
    validated_page_index: int | None = None
    rendered_bbox: Rect | None = None
    if (
        type(rendered_page_index) is int
        and rendered_page_index >= 0
        and isinstance(rendered_bbox_data, dict)
    ):
        try:
            candidate = Rect.model_validate(rendered_bbox_data)
        except ValidationError:
            pass
        else:
            coordinates = (candidate.x0, candidate.y0, candidate.x1, candidate.y1)
            if (
                all(isfinite(value) for value in coordinates)
                and candidate.x0 <= candidate.x1
                and candidate.y0 <= candidate.y1
            ):
                validated_page_index = rendered_page_index
                rendered_bbox = candidate
    return EvidenceRef(
        block_id=block.id,
        page_index=block.page_index,
        bbox=block.bbox,
        rendered_page_index=validated_page_index,
        rendered_bbox=rendered_bbox,
    )


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


def _clause_ids(drafts: list[_ClauseDraft]) -> list[str]:
    base_ids = [_clause_id(draft) for draft in drafts]
    base_counts = {base_id: base_ids.count(base_id) for base_id in base_ids}
    duplicate_occurrences: dict[tuple[str, str], int] = {}
    ids: list[str] = []
    for base_id, draft in zip(base_ids, drafts, strict=True):
        if base_counts[base_id] == 1:
            ids.append(base_id)
            continue
        full_text = fingerprint("\n".join(block.text for block in draft.blocks))
        occurrence_key = (base_id, full_text)
        occurrence = duplicate_occurrences.get(occurrence_key, 0)
        duplicate_occurrences[occurrence_key] = occurrence + 1
        material = f"{base_id}\0{full_text}\0{occurrence}".encode("utf-8")
        ids.append(f"clause-{hashlib.sha256(material).hexdigest()[:24]}")
    return ids


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


def _rects_are_near(first: Rect | None, second: Rect | None, distance: float = 24.0) -> bool:
    if first is None or second is None:
        return False
    horizontal_gap = max(first.x0 - second.x1, second.x0 - first.x1, 0.0)
    vertical_gap = max(first.y0 - second.y1, second.y0 - first.y1, 0.0)
    return horizontal_gap <= distance and vertical_gap <= distance


def _image_matches_block(feature: DocumentFeature, block: ContentBlock) -> bool:
    if feature.kind is not DocumentFeatureKind.EMBEDDED_IMAGE:
        return False
    for evidence in feature.evidence:
        if evidence.block_id == block.id:
            return True
        if (
            evidence.page_index is not None
            and evidence.page_index == block.page_index
            and _rects_are_near(evidence.bbox, block.bbox)
        ):
            return True
    return False


def _protected_region(
    block: ContentBlock, kind: ProtectedRegionKind, features: list[DocumentFeature]
) -> ProtectedRegion:
    text_fingerprint = fingerprint(block.text)
    material = f"{kind.value}\0{text_fingerprint}\0{block.id}".encode()
    matched_features = [feature for feature in features if _image_matches_block(feature, block)]
    evidence = [_evidence(block)]
    for feature in matched_features:
        for item in feature.evidence:
            if item not in evidence:
                evidence.append(item)
    return ProtectedRegion(
        id=f"region-{hashlib.sha256(material).hexdigest()[:24]}",
        kind=kind,
        text_fingerprint=text_fingerprint,
        evidence=evidence,
        feature_fingerprints=sorted(feature.fingerprint for feature in matched_features),
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
    raw_features = snapshot.metadata.get("document_features", [])
    if not isinstance(raw_features, list):
        raise TypeError("document_features metadata must be a list")
    features = [DocumentFeature.model_validate(item) for item in raw_features]
    raw_visible_text = snapshot.metadata.get(CONTRACT_VISIBLE_TEXT_METADATA_KEY)
    if raw_visible_text is not None and not isinstance(raw_visible_text, dict):
        raise TypeError(f"{CONTRACT_VISIBLE_TEXT_METADATA_KEY} metadata must be an object")
    visible_text_by_block = raw_visible_text or {}
    contract_blocks: list[ContentBlock] = []
    for block in snapshot.blocks:
        visible_text = visible_text_by_block.get(block.id, block.text)
        if not isinstance(visible_text, str):
            raise TypeError(f"{CONTRACT_VISIBLE_TEXT_METADATA_KEY} values must be strings")
        if not normalize_text(visible_text):
            continue
        contract_blocks.append(
            block.model_copy(
                update={
                    "text": visible_text,
                    "normalized_text": normalize_text(visible_text),
                }
            )
        )

    for block in contract_blocks:
        region_kind = _region_kind(block)
        if region_kind is not None:
            protected_regions.append(_protected_region(block, region_kind, features))
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

    ids = _clause_ids(drafts)
    clauses: list[ContractClause] = []
    all_entities = []
    for index, draft in enumerate(drafts):
        text = "\n".join(block.text for block in draft.blocks)
        clause_entities = [
            entity
            for block_index, block in enumerate(draft.blocks)
            for entity in extract_entities(
                block.text,
                ids[index],
                _evidence(block),
                block_index=block_index,
            )
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
        language=detect_language("\n".join(block.text for block in contract_blocks)),
        clauses=clauses,
        tables=tables,
        protected_regions=protected_regions,
        entities=all_entities,
        features=features,
        warnings=list(snapshot.warnings),
    )
