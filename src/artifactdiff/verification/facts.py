"""Deterministic, policy-neutral contract fact extraction."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Hashable, Iterable
from typing import Literal, TypeVar

from artifactdiff.contract.models import (
    ContractClause,
    ContractDocument,
    DocumentFeature,
    EntityKind,
    EvidenceRef,
    ProtectedEntity,
    ProtectedRegion,
)
from artifactdiff.normalize import comparison_text, normalize_text
from artifactdiff.verification.models import (
    ClauseChange,
    ClauseChangeKind,
    ContractChangeSet,
    EntityChange,
    FeatureChange,
    RegionChange,
)

_Item = TypeVar("_Item")
_GroupKey = TypeVar("_GroupKey", bound=Hashable)
_Change = TypeVar("_Change")
_NON_BUSINESS_METADATA_KEYS = frozenset(
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


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fact_id(kind: str, location: str, before: str, after: str) -> str:
    raw = json.dumps(
        [kind, location, before, after], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return f"fact-{hashlib.sha256(raw).hexdigest()[:24]}"


def _stable_evidence(items: list[EvidenceRef]) -> list[EvidenceRef]:
    return sorted(items, key=lambda item: _canonical(item.model_dump(mode="json")))


def _identity(clause: ContractClause) -> tuple[str, tuple[str, ...], str]:
    return (
        normalize_text(clause.label.normalized),
        tuple(normalize_text(item) for item in clause.ancestor_path),
        normalize_text(clause.heading),
    )


def _clause_location(before: ContractClause | None, after: ContractClause | None) -> str:
    before_identity = _identity(before) if before is not None else None
    after_identity = _identity(after) if after is not None else None
    return _canonical([before_identity, after_identity])


def _clause_semantic_key(
    clause: ContractClause,
) -> tuple[tuple[str, tuple[str, ...], str], str]:
    return (_identity(clause), clause.fingerprint)


def _unique_pairs(
    before: list[int],
    after: list[int],
    before_clauses: list[ContractClause],
    after_clauses: list[ContractClause],
    key: Callable[[ContractClause], _GroupKey],
) -> list[tuple[int, int]]:
    before_groups: dict[_GroupKey, list[int]] = defaultdict(list)
    after_groups: dict[_GroupKey, list[int]] = defaultdict(list)
    for index in before:
        before_groups[key(before_clauses[index])].append(index)
    for index in after:
        after_groups[key(after_clauses[index])].append(index)
    return [
        (before_groups[group_key][0], after_groups[group_key][0])
        for group_key in sorted(before_groups.keys() & after_groups.keys(), key=repr)
        if len(before_groups[group_key]) == len(after_groups[group_key]) == 1
    ]


def _pair_clauses(
    baseline: ContractDocument, candidate: ContractDocument
) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    before_remaining = list(range(len(baseline.clauses)))
    after_remaining = list(range(len(candidate.clauses)))
    pairs = _unique_pairs(
        before_remaining, after_remaining, baseline.clauses, candidate.clauses, _identity
    )
    paired_before = {before for before, _ in pairs}
    paired_after = {after for _, after in pairs}
    before_remaining = [index for index in before_remaining if index not in paired_before]
    after_remaining = [index for index in after_remaining if index not in paired_after]

    fingerprint_pairs = _unique_pairs(
        before_remaining,
        after_remaining,
        baseline.clauses,
        candidate.clauses,
        lambda clause: clause.fingerprint,
    )
    pairs.extend(fingerprint_pairs)
    paired_before = {before for before, _ in fingerprint_pairs}
    paired_after = {after for _, after in fingerprint_pairs}
    before_remaining = [index for index in before_remaining if index not in paired_before]
    after_remaining = [index for index in after_remaining if index not in paired_after]

    # Clauses without a separate heading use their first sentence as heading, so an
    # edit there changes both identity and fingerprint. A label (with its ancestors)
    # that is unique on both sides still identifies the clause; the pair is then
    # reported as modified and must be explained like any other change.
    label_pairs = _unique_pairs(
        [index for index in before_remaining if baseline.clauses[index].label.normalized],
        [index for index in after_remaining if candidate.clauses[index].label.normalized],
        baseline.clauses,
        candidate.clauses,
        _label_key,
    )
    label_pairs = [
        (before, after)
        for before, after in label_pairs
        if _label_is_unique(baseline, before) and _label_is_unique(candidate, after)
    ]
    pairs.extend(label_pairs)
    paired_before = {before for before, _ in label_pairs}
    paired_after = {after for _, after in label_pairs}
    return (
        pairs,
        [index for index in before_remaining if index not in paired_before],
        [index for index in after_remaining if index not in paired_after],
    )


def _label_key(clause: ContractClause) -> tuple[str, tuple[str, ...]]:
    return (
        normalize_text(clause.label.normalized),
        tuple(normalize_text(item) for item in clause.ancestor_path),
    )


def _label_is_unique(document: ContractDocument, index: int) -> bool:
    key = _label_key(document.clauses[index])
    return sum(1 for clause in document.clauses if _label_key(clause) == key) == 1


def _entity_counter(entities: Iterable[ProtectedEntity]) -> Counter[tuple[EntityKind, str]]:
    return Counter((entity.kind, entity.normalized_value) for entity in entities)


def _entities_differ(before: ContractClause, after: ContractClause) -> bool:
    return _entity_counter(before.entities) != _entity_counter(after.entities)


def _clause_change(
    kind: ClauseChangeKind,
    before: ContractClause | None,
    after: ContractClause | None,
    *,
    occurrence_id: str | None = None,
) -> ClauseChange:
    location = _clause_location(before, after)
    if occurrence_id is not None:
        location = _canonical([location, ["clause_id", occurrence_id]])
    return ClauseChange(
        id=_fact_id(
            f"clause:{kind.value}",
            location,
            before.fingerprint if before is not None else "",
            after.fingerprint if after is not None else "",
        ),
        kind=kind,
        before_clause_id=before.id if before is not None else None,
        after_clause_id=after.id if after is not None else None,
        before_text=before.text if before is not None else None,
        after_text=after.text if after is not None else None,
        before_evidence=_stable_evidence(before.evidence) if before is not None else [],
        after_evidence=_stable_evidence(after.evidence) if after is not None else [],
    )


def _entity_changes(
    before: ContractClause, after: ContractClause, clause_change_id: str
) -> list[EntityChange]:
    before_counts = _entity_counter(before.entities)
    after_counts = _entity_counter(after.entities)
    common = before_counts & after_counts
    before_counts -= common
    after_counts -= common
    changes: list[EntityChange] = []
    for kind in EntityKind:
        before_values = sorted(
            value
            for (entity_kind, value), count in before_counts.items()
            if entity_kind is kind
            for _ in range(count)
        )
        after_values = sorted(
            value
            for (entity_kind, value), count in after_counts.items()
            if entity_kind is kind
            for _ in range(count)
        )
        if len(before_values) == len(after_values) == 1:
            pairs = [(before_values[0], after_values[0], 0)]
        else:
            pairs = [(value, "", index) for index, value in enumerate(before_values)]
            pairs.extend(("", value, index) for index, value in enumerate(after_values))
        location = _canonical([_clause_location(before, after), kind.value])
        for before_value, after_value, occurrence in pairs:
            occurrence_location = _canonical([location, occurrence])
            changes.append(
                EntityChange(
                    id=_fact_id(
                        f"entity:{kind.value}",
                        occurrence_location,
                        before_value,
                        after_value,
                    ),
                    kind=kind,
                    before_value=before_value or None,
                    after_value=after_value or None,
                    clause_change_id=clause_change_id,
                )
            )
    return changes


def _classify_unmatched(
    before_indexes: list[int],
    after_indexes: list[int],
    before_clauses: list[ContractClause],
    after_clauses: list[ContractClause],
) -> tuple[list[int], list[int], list[int], list[int]]:
    before_identity = Counter(_identity(before_clauses[index]) for index in before_indexes)
    after_identity = Counter(_identity(after_clauses[index]) for index in after_indexes)
    before_fingerprint = Counter(before_clauses[index].fingerprint for index in before_indexes)
    after_fingerprint = Counter(after_clauses[index].fingerprint for index in after_indexes)

    def is_unresolved(
        clause: ContractClause,
        own_identity: Counter[tuple[str, tuple[str, ...], str]],
        other_identity: Counter[tuple[str, tuple[str, ...], str]],
        own_fingerprint: Counter[str],
        other_fingerprint: Counter[str],
    ) -> bool:
        identity = _identity(clause)
        fingerprint_value = clause.fingerprint
        identity_tied = other_identity[identity] > 0 and (
            own_identity[identity] > 1 or other_identity[identity] > 1
        )
        fingerprint_tied = other_fingerprint[fingerprint_value] > 0 and (
            own_fingerprint[fingerprint_value] > 1 or other_fingerprint[fingerprint_value] > 1
        )
        return identity_tied or fingerprint_tied

    unresolved_before = [
        index
        for index in before_indexes
        if is_unresolved(
            before_clauses[index],
            before_identity,
            after_identity,
            before_fingerprint,
            after_fingerprint,
        )
    ]
    unresolved_after = [
        index
        for index in after_indexes
        if is_unresolved(
            after_clauses[index],
            after_identity,
            before_identity,
            after_fingerprint,
            before_fingerprint,
        )
    ]
    unique_before = [index for index in before_indexes if index not in unresolved_before]
    unique_after = [index for index in after_indexes if index not in unresolved_after]

    def indistinguishable_occurrences(
        indexes: list[int], clauses: list[ContractClause]
    ) -> list[int]:
        id_counts: dict[tuple[tuple[str, tuple[str, ...], str], str], Counter[str]] = defaultdict(
            Counter
        )
        for index in indexes:
            clause = clauses[index]
            id_counts[_clause_semantic_key(clause)][clause.id] += 1
        return [
            index
            for index in indexes
            if id_counts[_clause_semantic_key(clauses[index])][clauses[index].id] > 1
        ]

    duplicate_before = indistinguishable_occurrences(unique_before, before_clauses)
    duplicate_after = indistinguishable_occurrences(unique_after, after_clauses)
    return (
        [index for index in unique_before if index not in duplicate_before],
        [*unresolved_before, *duplicate_before],
        [index for index in unique_after if index not in duplicate_after],
        [*unresolved_after, *duplicate_after],
    )


def _unmatched_clause_changes(
    kind: ClauseChangeKind,
    indexes: list[int],
    clauses: list[ContractClause],
) -> list[ClauseChange]:
    group_counts = Counter(_clause_semantic_key(clauses[index]) for index in indexes)
    changes: list[ClauseChange] = []
    for index in sorted(
        indexes,
        key=lambda item: (*_clause_semantic_key(clauses[item]), clauses[item].id),
    ):
        clause = clauses[index]
        occurrence_id = clause.id if group_counts[_clause_semantic_key(clause)] > 1 else None
        changes.append(
            _clause_change(
                kind,
                clause if kind is ClauseChangeKind.REMOVED else None,
                clause if kind is ClauseChangeKind.ADDED else None,
                occurrence_id=occurrence_id,
            )
        )
    return changes


def _diff_clauses(
    baseline: ContractDocument, candidate: ContractDocument
) -> tuple[list[ClauseChange], list[EntityChange], list[str]]:
    pairs, before_unmatched, after_unmatched = _pair_clauses(baseline, candidate)
    before_rank = {before_index: rank for rank, (before_index, _) in enumerate(sorted(pairs))}
    after_rank = {
        after_index: rank
        for rank, (_, after_index) in enumerate(sorted(pairs, key=lambda pair: pair[1]))
    }
    clause_changes: list[ClauseChange] = []
    entity_changes: list[EntityChange] = []
    for before_index, after_index in pairs:
        before = baseline.clauses[before_index]
        after = candidate.clauses[after_index]
        modified = comparison_text(before.text) != comparison_text(after.text) or (
            _entities_differ(before, after)
        )
        moved = (
            tuple(normalize_text(item) for item in before.ancestor_path)
            != tuple(normalize_text(item) for item in after.ancestor_path)
            or before_rank[before_index] != after_rank[after_index]
        )
        if not modified and not moved:
            continue
        change = _clause_change(
            ClauseChangeKind.MODIFIED if modified else ClauseChangeKind.MOVED,
            before,
            after,
        )
        clause_changes.append(change)
        if _entities_differ(before, after):
            entity_changes.extend(_entity_changes(before, after, change.id))

    (
        unique_before,
        unresolved_before,
        unique_after,
        unresolved_after,
    ) = _classify_unmatched(
        before_unmatched,
        after_unmatched,
        baseline.clauses,
        candidate.clauses,
    )
    clause_changes.extend(
        _unmatched_clause_changes(ClauseChangeKind.REMOVED, unique_before, baseline.clauses)
    )
    clause_changes.extend(
        _unmatched_clause_changes(ClauseChangeKind.ADDED, unique_after, candidate.clauses)
    )
    unresolved_ids = sorted(
        [baseline.clauses[index].id for index in unresolved_before]
        + [candidate.clauses[index].id for index in unresolved_after]
    )
    return (
        sorted(clause_changes, key=lambda item: item.id),
        sorted(entity_changes, key=lambda item: item.id),
        unresolved_ids,
    )


def _region_fingerprint(region: ProtectedRegion) -> str:
    payload = _canonical([region.text_fingerprint, sorted(region.feature_fingerprints)]).encode(
        "utf-8"
    )
    return hashlib.sha256(payload).hexdigest()


def _is_non_business(feature: DocumentFeature) -> bool:
    relevance = feature.details.get("business_relevance")
    metadata_key = feature.details.get("metadata_key")
    return (
        feature.kind.value == "metadata"
        and isinstance(relevance, str)
        and relevance == "non_business"
        and isinstance(metadata_key, str)
        and len(metadata_key) <= 128
        and normalize_text(metadata_key) in _NON_BUSINESS_METADATA_KEYS
    )


def _feature_group(feature: DocumentFeature) -> str:
    stable_details: dict[str, str] = {}

    def normalized_detail(key: str, pattern: str, maximum: int) -> str | None:
        value = feature.details.get(key)
        if not isinstance(value, str) or not 0 < len(value) <= maximum:
            return None
        normalized = normalize_text(value)
        return normalized if re.fullmatch(pattern, normalized) else None

    if feature.kind.value == "metadata":
        metadata_key = normalized_detail("metadata_key", r"[a-z][a-z0-9_.-]{0,127}", 128)
        if metadata_key is not None:
            stable_details["metadata_key"] = metadata_key
        stable_details["business_relevance"] = (
            "non_business" if _is_non_business(feature) else "business"
        )
    elif feature.kind.value == "external_link":
        host_hash = normalized_detail("host_hash", r"[0-9a-f]{64}", 64)
        uri_scheme = normalized_detail("uri_scheme", r"[a-z][a-z0-9+.-]{0,31}", 32)
        if host_hash is not None:
            stable_details["host_hash"] = host_hash
        if uri_scheme is not None:
            stable_details["uri_scheme"] = uri_scheme
    elif feature.kind.value == "tracked_revision":
        revision_type = normalized_detail("revision_type", r"(?:insertion|deletion)", 9)
        if revision_type is not None:
            stable_details["revision_type"] = revision_type
    elif feature.kind.value == "hidden_text":
        hidden_kind = normalized_detail(
            "hidden_kind", r"(?:vanish|webhidden)(?:\+(?:vanish|webhidden))?", 32
        )
        if hidden_kind is not None:
            stable_details["hidden_kind"] = hidden_kind
    return _canonical([feature.kind.value, stable_details])


def _diff_grouped_fingerprints(
    before_items: Iterable[_Item],
    after_items: Iterable[_Item],
    *,
    group: Callable[[_Item], str],
    item_fingerprint: Callable[[_Item], str],
    make_change: Callable[[_Item | None, _Item | None, str], _Change],
) -> list[_Change]:
    before_groups: dict[str, list[_Item]] = defaultdict(list)
    after_groups: dict[str, list[_Item]] = defaultdict(list)
    for item in before_items:
        before_groups[group(item)].append(item)
    for item in after_items:
        after_groups[group(item)].append(item)
    changes: list[_Change] = []
    for group_key in sorted(before_groups.keys() | after_groups.keys()):
        before_by_fp: dict[str, list[_Item]] = defaultdict(list)
        after_by_fp: dict[str, list[_Item]] = defaultdict(list)
        for item in before_groups[group_key]:
            before_by_fp[item_fingerprint(item)].append(item)
        for item in after_groups[group_key]:
            after_by_fp[item_fingerprint(item)].append(item)
        for fingerprint_value in before_by_fp.keys() & after_by_fp.keys():
            common = min(len(before_by_fp[fingerprint_value]), len(after_by_fp[fingerprint_value]))
            del before_by_fp[fingerprint_value][:common]
            del after_by_fp[fingerprint_value][:common]
        before_remaining = sorted(
            (item for items in before_by_fp.values() for item in items),
            key=item_fingerprint,
        )
        after_remaining = sorted(
            (item for items in after_by_fp.values() for item in items),
            key=item_fingerprint,
        )
        if len(before_remaining) == len(after_remaining) == 1:
            changes.append(make_change(before_remaining[0], after_remaining[0], group_key))
        else:
            changes.extend(
                make_change(item, None, _canonical([group_key, "removed", index]))
                for index, item in enumerate(before_remaining)
            )
            changes.extend(
                make_change(None, item, _canonical([group_key, "added", index]))
                for index, item in enumerate(after_remaining)
            )
    return changes


def _diff_regions(baseline: ContractDocument, candidate: ContractDocument) -> list[RegionChange]:
    def make_change(
        before: ProtectedRegion | None, after: ProtectedRegion | None, location: str
    ) -> RegionChange:
        before_fp = _region_fingerprint(before) if before is not None else ""
        after_fp = _region_fingerprint(after) if after is not None else ""
        source = before if before is not None else after
        if source is None:
            raise AssertionError("region change requires at least one side")
        kind = source.kind
        return RegionChange(
            id=_fact_id(f"region:{kind.value}", location, before_fp, after_fp),
            kind=kind,
            before_fingerprint=before_fp or None,
            after_fingerprint=after_fp or None,
        )

    return sorted(
        _diff_grouped_fingerprints(
            baseline.protected_regions,
            candidate.protected_regions,
            group=lambda item: item.kind.value,
            item_fingerprint=_region_fingerprint,
            make_change=make_change,
        ),
        key=lambda item: item.id,
    )


def _expanded_features(features: Iterable[DocumentFeature]) -> Iterable[DocumentFeature]:
    for feature in features:
        yield from (feature for _ in range(feature.count))


def _diff_features(baseline: ContractDocument, candidate: ContractDocument) -> list[FeatureChange]:
    def make_change(
        before: DocumentFeature | None, after: DocumentFeature | None, location: str
    ) -> FeatureChange:
        before_fp = before.fingerprint if before is not None else ""
        after_fp = after.fingerprint if after is not None else ""
        source = before if before is not None else after
        if source is None:
            raise AssertionError("feature change requires at least one side")
        kind = source.kind
        relevant_items = [item for item in (before, after) if item is not None]
        relevance: Literal["business", "non_business"] = (
            "non_business"
            if relevant_items and all(_is_non_business(item) for item in relevant_items)
            else "business"
        )
        return FeatureChange(
            id=_fact_id(f"feature:{kind.value}", location, before_fp, after_fp),
            kind=kind,
            before_fingerprint=before_fp or None,
            after_fingerprint=after_fp or None,
            business_relevance=relevance,
        )

    return sorted(
        _diff_grouped_fingerprints(
            _expanded_features(baseline.features),
            _expanded_features(candidate.features),
            group=_feature_group,
            item_fingerprint=lambda item: item.fingerprint,
            make_change=make_change,
        ),
        key=lambda item: item.id,
    )


def diff_contracts(baseline: ContractDocument, candidate: ContractDocument) -> ContractChangeSet:
    """Return deterministic observed facts without making authorization decisions."""
    clause_changes, entity_changes, unresolved_ids = _diff_clauses(baseline, candidate)
    return ContractChangeSet(
        baseline_sha256=baseline.source.sha256,
        candidate_sha256=candidate.source.sha256,
        clause_changes=clause_changes,
        entity_changes=entity_changes,
        region_changes=_diff_regions(baseline, candidate),
        feature_changes=_diff_features(baseline, candidate),
        unresolved_clause_ids=unresolved_ids,
    )
