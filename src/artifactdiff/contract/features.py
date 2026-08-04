"""Bounded, deterministic feature extraction for DOCX and PDF documents."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from pdfplumber.pdf import PDF
from pydantic import JsonValue

from artifactdiff.contract.models import (
    DocumentFeature,
    DocumentFeatureKind,
    EvidenceRef,
)
from artifactdiff.models import ContentType, Rect
from artifactdiff.normalize import fingerprint, normalize_text

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

_W_P = f"{{{W}}}p"
_W_T = f"{{{W}}}t"
_W_TAB = f"{{{W}}}tab"
_W_BR = f"{{{W}}}br"
_W_INS = f"{{{W}}}ins"
_W_DEL = f"{{{W}}}del"
_W_R = f"{{{W}}}r"
_W_COMMENT = f"{{{W}}}comment"
_W_COMMENT_REFERENCE = f"{{{W}}}commentReference"
_A_BLIP = f"{{{A}}}blip"
_RELATIONSHIP = f"{{{PKG_REL}}}Relationship"

_NON_BUSINESS_METADATA = frozenset(
    {
        "application",
        "appversion",
        "created",
        "creator",
        "creationdate",
        "lastmodifiedby",
        "modified",
        "moddate",
        "producer",
    }
)
_PDF_VOLATILE_METADATA = frozenset({"filename", "filepath", "source"})


class FeatureInspectionError(ValueError):
    """Raised when feature structures cannot be inspected safely."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_details(details: Mapping[str, JsonValue]) -> str:
    return json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _make_feature(
    kind: DocumentFeatureKind,
    content_fingerprint: str,
    *,
    count: int = 1,
    evidence: list[EvidenceRef] | None = None,
    details: dict[str, JsonValue] | None = None,
) -> DocumentFeature:
    stable_evidence = sorted(
        evidence or [],
        key=lambda item: (
            item.block_id,
            item.page_index if item.page_index is not None else -1,
            tuple(item.bbox.model_dump().values()) if item.bbox is not None else (),
        ),
    )
    stable_details = details or {}
    material = "\0".join(
        (
            kind.value,
            _canonical_details(stable_details),
            ",".join(item.block_id for item in stable_evidence),
            content_fingerprint,
        )
    ).encode("utf-8")
    return DocumentFeature(
        id=f"feature-{_sha256(material)[:24]}",
        kind=kind,
        fingerprint=content_fingerprint,
        count=count,
        evidence=stable_evidence,
        details=stable_details,
    )


def _merge_and_sort(features: list[DocumentFeature]) -> list[DocumentFeature]:
    merged: dict[str, DocumentFeature] = {}
    for feature in features:
        existing = merged.get(feature.id)
        if existing is None:
            merged[feature.id] = feature
        else:
            existing.count += feature.count
    return sorted(
        merged.values(),
        key=lambda item: (
            item.kind.value,
            _canonical_details(item.details),
            tuple(evidence.block_id for evidence in item.evidence),
            item.fingerprint,
        ),
    )


def _xml(payload: bytes, part_name: str) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        raise FeatureInspectionError(f"malformed OOXML part: {part_name}") from error


def _relationship_owner(part_name: str) -> str | None:
    path = PurePosixPath(part_name)
    if path.parent.name != "_rels" or not path.name.endswith(".rels"):
        return None
    owner_name = path.name.removesuffix(".rels")
    owner_parent = path.parent.parent
    return str(owner_parent / owner_name) if str(owner_parent) != "." else owner_name


def _relationship_target(owner: str, target: str) -> str:
    if target.startswith("/"):
        return target.lstrip("/")
    parts: list[str] = []
    for part in (PurePosixPath(owner).parent / target).parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    return "/".join(parts)


def _paragraph_text(paragraph: ElementTree.Element) -> str:
    pieces: list[str] = []

    def visit(node: ElementTree.Element) -> None:
        if node.tag in {_W_INS, _W_DEL}:
            return
        if node.tag == _W_R:
            properties = node.find(f"{{{W}}}rPr")
            if properties is not None and any(
                properties.find(f"{{{W}}}{kind}") is not None
                for kind in ("vanish", "webHidden")
            ):
                return
        if node.tag == _W_T and node.text:
            pieces.append(node.text)
        elif node.tag == _W_TAB:
            pieces.append("\t")
        elif node.tag == _W_BR:
            pieces.append("\n")
        for child in node:
            visit(child)

    visit(paragraph)
    return "".join(pieces).strip()


def _document_evidence(
    root: ElementTree.Element,
) -> tuple[dict[int, EvidenceRef], dict[int, EvidenceRef]]:
    body = root.find(f".//{{{W}}}body")
    if body is None:
        return {}, {}
    paragraph_evidence: dict[int, EvidenceRef] = {}
    descendant_evidence: dict[int, EvidenceRef] = {}
    ordinal = 0
    for child in body:
        if child.tag == _W_P:
            text = _paragraph_text(child)
            if not text:
                continue
            style = child.find(f"./{{{W}}}pPr/{{{W}}}pStyle")
            style_value = style.get(f"{{{W}}}val", "") if style is not None else ""
            content_type = (
                ContentType.HEADING if style_value.startswith("Heading") else ContentType.PARAGRAPH
            )
            block_id = f"docx:{ordinal}:{content_type}:{fingerprint(text)}"
            evidence = EvidenceRef(block_id=block_id)
            paragraph_evidence[id(child)] = evidence
            for descendant in child.iter():
                descendant_evidence[id(descendant)] = evidence
            ordinal += 1
        elif child.tag == f"{{{W}}}tbl":
            table_text = "".join(node.text or "" for node in child.iter(_W_T))
            if table_text.strip():
                ordinal += 1
    return paragraph_evidence, descendant_evidence


def _metadata_features(roots: Mapping[str, ElementTree.Element]) -> list[DocumentFeature]:
    features: list[DocumentFeature] = []
    for part_name in ("docProps/app.xml", "docProps/core.xml"):
        root = roots.get(part_name)
        if root is None:
            continue
        for node in sorted(root, key=lambda item: item.tag.rsplit("}", 1)[-1].casefold()):
            value = normalize_text("".join(node.itertext()))
            if not value:
                continue
            key = node.tag.rsplit("}", 1)[-1].casefold()
            details: dict[str, JsonValue] = {"metadata_key": key, "part_name": part_name}
            if key in _NON_BUSINESS_METADATA:
                details["business_relevance"] = "non_business"
            features.append(
                _make_feature(
                    DocumentFeatureKind.METADATA,
                    fingerprint(value),
                    details=details,
                )
            )
    return features


def _sanitized_uri(target: str) -> tuple[str, str, str]:
    normalized_target = normalize_text(target)
    split = urlsplit(normalized_target)
    scheme = split.scheme.casefold()
    host_hash = _sha256((split.hostname or "").casefold().encode("utf-8"))
    return scheme, host_hash, _sha256(normalized_target.encode("utf-8"))


def inspect_docx_features(path: Path) -> list[DocumentFeature]:
    """Inspect bounded OOXML feature facts from a validated DOCX package."""
    try:
        with ZipFile(path) as package:
            payloads = {
                name: package.read(name)
                for name in sorted(package.namelist())
                if not name.endswith("/")
            }
    except (BadZipFile, KeyError, OSError) as error:
        raise FeatureInspectionError("invalid OOXML package") from error

    roots = {
        name: _xml(payload, name)
        for name, payload in payloads.items()
        if name.endswith((".xml", ".rels"))
    }
    relationships: dict[str, dict[str, ElementTree.Element]] = {}
    for part_name in sorted(name for name in roots if name.endswith(".rels")):
        owner = _relationship_owner(part_name)
        if owner is None:
            continue
        relationships[owner] = {
            node.get("Id", ""): node for node in roots[part_name].iter(_RELATIONSHIP)
        }

    main_root = roots.get("word/document.xml")
    descendants: dict[int, EvidenceRef] = {}
    if main_root is not None:
        _, descendants = _document_evidence(main_root)

    features = _metadata_features(roots)
    content_parts = [
        name
        for name in sorted(roots)
        if name.startswith(("word/document.xml", "word/header", "word/footer"))
        or name in {"word/endnotes.xml", "word/footnotes.xml"}
    ]

    comment_text: dict[str, str] = {}
    comments_root = roots.get("word/comments.xml")
    if comments_root is not None:
        for comment in comments_root.iter(_W_COMMENT):
            comment_id = comment.get(f"{{{W}}}id", "")
            comment_text[comment_id] = " ".join(node.text or "" for node in comment.iter(_W_T))
    comment_evidence: dict[str, list[EvidenceRef]] = defaultdict(list)

    for part_name in content_parts:
        root = roots[part_name]
        for node in root.iter():
            evidence = [descendants[id(node)]] if id(node) in descendants else []
            if node.tag == _W_COMMENT_REFERENCE:
                comment_id = node.get(f"{{{W}}}id", "")
                comment_evidence[comment_id].extend(evidence)
            elif node.tag in {_W_INS, _W_DEL}:
                revision_text = " ".join(item.text or "" for item in node.iter(_W_T))
                features.append(
                    _make_feature(
                        DocumentFeatureKind.TRACKED_REVISION,
                        fingerprint(revision_text),
                        evidence=evidence,
                        details={
                            "part_name": part_name,
                            "revision_type": "insertion" if node.tag == _W_INS else "deletion",
                        },
                    )
                )
            elif node.tag == _W_R:
                properties = node.find(f"{{{W}}}rPr")
                if properties is None:
                    continue
                hidden_kinds = [
                    kind
                    for kind in ("vanish", "webHidden")
                    if properties.find(f"{{{W}}}{kind}") is not None
                ]
                if hidden_kinds:
                    hidden_text = " ".join(item.text or "" for item in node.iter(_W_T))
                    features.append(
                        _make_feature(
                            DocumentFeatureKind.HIDDEN_TEXT,
                            fingerprint(hidden_text),
                            evidence=evidence,
                            details={
                                "hidden_kind": "+".join(hidden_kinds),
                                "part_name": part_name,
                            },
                        )
                    )

        for relationship in relationships.get(part_name, {}).values():
            if relationship.get("TargetMode") != "External":
                continue
            target = relationship.get("Target")
            if target is None:
                raise FeatureInspectionError(f"external relationship has no target: {part_name}")
            scheme, host_hash, target_fingerprint = _sanitized_uri(target)
            rel_type = relationship.get("Type", "").rsplit("/", 1)[-1]
            relationship_id = relationship.get("Id", "")
            evidence = []
            for node in root.iter():
                if relationship_id and relationship_id in node.attrib.values():
                    if id(node) in descendants:
                        evidence = [descendants[id(node)]]
                    break
            features.append(
                _make_feature(
                    DocumentFeatureKind.EXTERNAL_LINK,
                    target_fingerprint,
                    evidence=evidence,
                    details={
                        "host_hash": host_hash,
                        "part_name": part_name,
                        "relationship_type": rel_type,
                        "uri_scheme": scheme,
                    },
                )
            )

        for blip in root.iter(_A_BLIP):
            blip_relationship_id = blip.get(f"{{{R}}}embed")
            image_relationship = relationships.get(part_name, {}).get(
                blip_relationship_id or ""
            )
            if image_relationship is None:
                raise FeatureInspectionError(f"image relationship is missing: {part_name}")
            target = image_relationship.get("Target")
            if target is None:
                raise FeatureInspectionError(f"image relationship has no target: {part_name}")
            image_part = _relationship_target(part_name, target)
            image_bytes = payloads.get(image_part)
            if image_bytes is None:
                raise FeatureInspectionError(f"image part is missing: {image_part}")
            evidence = [descendants[id(blip)]] if id(blip) in descendants else []
            features.append(
                _make_feature(
                    DocumentFeatureKind.EMBEDDED_IMAGE,
                    _sha256(image_bytes),
                    evidence=evidence,
                    details={
                        "image_part": image_part,
                        "part_name": part_name,
                        "relationship_type": image_relationship.get("Type", "").rsplit(
                            "/", 1
                        )[-1],
                    },
                )
            )

    for comment_id in sorted(set(comment_text) | set(comment_evidence)):
        evidence_ids = list(
            dict.fromkeys(item.block_id for item in comment_evidence[comment_id])
        )
        evidence_by_id = {item.block_id: item for item in comment_evidence[comment_id]}
        value = comment_text.get(comment_id, f"comment-id:{comment_id}")
        features.append(
            _make_feature(
                DocumentFeatureKind.COMMENT,
                fingerprint(value),
                count=max(1, len(comment_evidence[comment_id])),
                evidence=[evidence_by_id[block_id] for block_id in evidence_ids],
                details={"part_name": "word/comments.xml"},
            )
        )
    return _merge_and_sort(features)


def _pdf_scalar(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    name = getattr(value, "name", None)
    if isinstance(name, (str, bytes)):
        return _pdf_scalar(name)
    raise FeatureInspectionError(f"unsupported PDF scalar: {type(value).__name__}")


def _pdf_bbox(item: Mapping[str, object]) -> Rect | None:
    try:
        x0 = float(_pdf_scalar(item["x0"]))
        x1 = float(_pdf_scalar(item["x1"]))
        top = float(_pdf_scalar(item["top"]))
        bottom = float(_pdf_scalar(item["bottom"]))
    except KeyError:
        return None
    except (TypeError, ValueError) as error:
        raise FeatureInspectionError("malformed PDF bounding box") from error
    return Rect(x0=x0, y0=top, x1=x1, y1=bottom)


def _annotation_uri(annotation: Mapping[str, object]) -> str | None:
    candidates: list[object] = [annotation.get("uri"), annotation.get("URI")]
    for key in ("A", "action"):
        action = annotation.get(key)
        if isinstance(action, Mapping):
            candidates.extend((action.get("URI"), action.get("uri")))
    data = annotation.get("data")
    if isinstance(data, Mapping):
        candidates.extend((data.get("URI"), data.get("uri")))
        action = data.get("A")
        if isinstance(action, Mapping):
            candidates.extend((action.get("URI"), action.get("uri")))
    for candidate in candidates:
        if candidate is not None:
            return _pdf_scalar(candidate)
    return None


def _pdf_image_fingerprint(
    image: Mapping[str, object], page_index: int, bbox: Rect | None
) -> tuple[str, str]:
    stream = image.get("stream")
    if stream is not None:
        for attribute in ("get_data",):
            method = getattr(stream, attribute, None)
            if callable(method):
                try:
                    data = method()
                except Exception as error:  # pdfminer exposes parser-specific failures
                    raise FeatureInspectionError("malformed PDF image stream") from error
                if isinstance(data, bytes):
                    return _sha256(data), "content"
        rawdata = getattr(stream, "rawdata", None)
        if isinstance(rawdata, bytes):
            return _sha256(rawdata), "content"
    object_id = image.get("object_id") or getattr(stream, "objid", None)
    if object_id is not None:
        return fingerprint(f"pdf-image-object:{_pdf_scalar(object_id)}"), "object"
    geometry = bbox.model_dump_json() if bbox is not None else "no-bbox"
    return fingerprint(f"pdf-image-geometry:{page_index}:{geometry}"), "geometry"


def inspect_pdf_features(document: PDF) -> list[DocumentFeature]:
    """Inspect bounded PDF metadata, external annotations, and image facts."""
    features: list[DocumentFeature] = []
    metadata = document.metadata or {}
    if not isinstance(metadata, Mapping):
        raise FeatureInspectionError("malformed PDF metadata")
    for raw_key in sorted(metadata, key=lambda item: str(item).casefold()):
        key = str(raw_key).lstrip("/").casefold()
        if key.startswith("_") or key in _PDF_VOLATILE_METADATA:
            continue
        raw_value = metadata[raw_key]
        if raw_value is None:
            continue
        value = normalize_text(_pdf_scalar(raw_value))
        if not value:
            continue
        details: dict[str, JsonValue] = {"metadata_key": key, "part_name": "pdf:info"}
        if key in _NON_BUSINESS_METADATA:
            details["business_relevance"] = "non_business"
        features.append(
            _make_feature(DocumentFeatureKind.METADATA, fingerprint(value), details=details)
        )

    for page_index, page in enumerate(document.pages):
        annotations = page.annots or []
        if not isinstance(annotations, list):
            raise FeatureInspectionError("malformed PDF annotations")
        for annotation_index, annotation in enumerate(annotations):
            if not isinstance(annotation, Mapping):
                raise FeatureInspectionError("malformed PDF annotation")
            target = _annotation_uri(annotation)
            if target is None:
                continue
            scheme, host_hash, target_fingerprint = _sanitized_uri(target)
            bbox = _pdf_bbox(annotation)
            evidence = EvidenceRef(
                block_id=f"pdf:{page_index}:annotation:{annotation_index}",
                page_index=page_index,
                bbox=bbox,
            )
            features.append(
                _make_feature(
                    DocumentFeatureKind.EXTERNAL_LINK,
                    target_fingerprint,
                    evidence=[evidence],
                    details={
                        "host_hash": host_hash,
                        "page_index": page_index,
                        "relationship_type": "annotation_uri",
                        "uri_scheme": scheme,
                    },
                )
            )

        images = page.images or []
        if not isinstance(images, list):
            raise FeatureInspectionError("malformed PDF images")
        for image_index, image in enumerate(images):
            if not isinstance(image, Mapping):
                raise FeatureInspectionError("malformed PDF image")
            bbox = _pdf_bbox(image)
            image_fingerprint, confidence = _pdf_image_fingerprint(image, page_index, bbox)
            evidence = EvidenceRef(
                block_id=f"pdf:{page_index}:image:{image_index}",
                page_index=page_index,
                bbox=bbox,
            )
            features.append(
                _make_feature(
                    DocumentFeatureKind.EMBEDDED_IMAGE,
                    image_fingerprint,
                    evidence=[evidence],
                    details={
                        "extraction_confidence": confidence,
                        "page_index": page_index,
                    },
                )
            )
    return _merge_and_sort(features)
