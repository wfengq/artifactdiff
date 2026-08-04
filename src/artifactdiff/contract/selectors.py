"""Strict models and deterministic contract clause selector resolution."""

import re
from difflib import SequenceMatcher
from enum import StrEnum
from math import fsum
from typing import Literal

from pydantic import Field, StrictInt, StrictStr, field_validator

from artifactdiff.contract.models import ContractClause, ContractDocument
from artifactdiff.models import StrictModel
from artifactdiff.normalize import normalize_text

LABEL_WEIGHT = 0.35
HEADING_WEIGHT = 0.25
ANCESTOR_WEIGHT = 0.15
ANCHOR_FINGERPRINT_WEIGHT = 0.25
FUZZY_ANCHOR_MIN_SIMILARITY = 0.90
MAX_FUZZY_ANCHOR_CHARACTERS = 4_096
MAX_FUZZY_CLAUSE_CHARACTERS = 32_768
MAX_FUZZY_CLAUSE_LINES = 256
MIN_NONNUMERIC_CONTEXT_CHARACTERS = 6
STABLE_VALUE_PATTERN = re.compile(r"\d+(?:[.,]\d+)*")


class ClauseSelector(StrictModel):
    clause_label: StrictStr
    heading: StrictStr
    ancestor_path: tuple[StrictStr, ...] = ()
    anchor: StrictStr
    baseline_fingerprint: StrictStr = ""
    occurrences: StrictInt = Field(default=1, ge=1, le=100)
    matcher_version: Literal["1.0"] = "1.0"
    min_similarity: float = Field(default=0.92, ge=0.0, le=1.0)
    min_margin: float = Field(default=0.05, ge=0.0, le=1.0)

    @field_validator("ancestor_path", mode="before")
    @classmethod
    def ancestor_path_is_ordered(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            # Pydantic turns ValueError, but not TypeError, into ValidationError.
            raise ValueError("ancestor path must be ordered")  # noqa: TRY004
        return value

    @field_validator("matcher_version", mode="before")
    @classmethod
    def matcher_version_is_text(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("matcher version must be text")  # noqa: TRY004
        return value

    @field_validator("min_similarity", "min_margin", mode="before")
    @classmethod
    def thresholds_are_numeric(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("selector threshold must be numeric")  # noqa: TRY004
        return value


class SelectorResolutionStatus(StrEnum):
    UNIQUE = "unique"
    HIGH_CONFIDENCE = "high_confidence"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"


class SelectorMatch(StrictModel):
    clause_id: str
    score: float = Field(ge=0.0, le=1.0)


class SelectorResolution(StrictModel):
    matcher_version: Literal["1.0"] = "1.0"
    status: SelectorResolutionStatus
    matches: list[SelectorMatch] = Field(default_factory=list)


def resolve_baseline(document: ContractDocument, selector: ClauseSelector) -> SelectorResolution:
    """Resolve an exact selector against a baseline contract."""
    matches = [
        SelectorMatch(clause_id=clause.id, score=1.0)
        for clause in document.clauses
        if _is_exact_match(clause, selector)
    ]
    matches.sort(key=lambda match: match.clause_id)
    if not matches:
        status = SelectorResolutionStatus.MISSING
    elif len(matches) == 1:
        status = SelectorResolutionStatus.UNIQUE
    else:
        status = SelectorResolutionStatus.AMBIGUOUS
    return SelectorResolution(status=status, matches=matches)


def resolve_candidate(document: ContractDocument, selector: ClauseSelector) -> SelectorResolution:
    """Resolve a conservative weighted selector against a candidate contract."""
    matches = [
        SelectorMatch(clause_id=clause.id, score=_candidate_score(clause, selector))
        for clause in document.clauses
        if _mandatory_fields_agree(clause, selector)
    ]
    matches.sort(key=lambda match: (-match.score, match.clause_id))
    if not matches or matches[0].score < selector.min_similarity:
        status = SelectorResolutionStatus.MISSING
    elif len(matches) > 1 and (
        matches[0].score == matches[1].score
        or matches[0].score - matches[1].score < selector.min_margin
    ):
        status = SelectorResolutionStatus.AMBIGUOUS
    else:
        status = SelectorResolutionStatus.HIGH_CONFIDENCE
    return SelectorResolution(status=status, matches=matches)


def _normalized_path(path: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(normalize_text(part) for part in path)


def _anchor_occurrences(clause: ContractClause, selector: ClauseSelector) -> int:
    anchor = normalize_text(selector.anchor)
    if not anchor:
        return 0
    return normalize_text(clause.normalized_text).count(anchor)


def _is_exact_match(clause: ContractClause, selector: ClauseSelector) -> bool:
    return (
        normalize_text(clause.label.normalized) == normalize_text(selector.clause_label)
        and normalize_text(clause.heading) == normalize_text(selector.heading)
        and _normalized_path(clause.ancestor_path) == _normalized_path(selector.ancestor_path)
        and _anchor_occurrences(clause, selector) == selector.occurrences
        and (
            not selector.baseline_fingerprint or clause.fingerprint == selector.baseline_fingerprint
        )
    )


def _mandatory_fields_agree(clause: ContractClause, selector: ClauseSelector) -> bool:
    return normalize_text(clause.label.normalized) == normalize_text(
        selector.clause_label
    ) and _normalized_path(clause.ancestor_path) == _normalized_path(selector.ancestor_path)


def _similarity(before: str, after: str) -> float:
    return SequenceMatcher(
        None, normalize_text(before), normalize_text(after), autojunk=False
    ).ratio()


def _has_sufficient_nonnumeric_context(value: str) -> bool:
    context_characters = sum(
        character.isalpha() for character in STABLE_VALUE_PATTERN.sub("", normalize_text(value))
    )
    return context_characters >= MIN_NONNUMERIC_CONTEXT_CHARACTERS


def _fuzzy_anchor_scores(clause: ContractClause, selector: ClauseSelector) -> list[float]:
    anchor = normalize_text(selector.anchor)
    lines = []
    for line in clause.text.splitlines():
        normalized = normalize_text(line)
        if normalized:
            lines.append(normalized)
    if (
        not anchor
        or len(anchor) > MAX_FUZZY_ANCHOR_CHARACTERS
        or len(lines) > MAX_FUZZY_CLAUSE_LINES
        or sum(len(line) for line in lines) > MAX_FUZZY_CLAUSE_CHARACTERS
        or any(len(line) > MAX_FUZZY_ANCHOR_CHARACTERS for line in lines)
    ):
        return []
    return [
        score
        for line in lines
        if (score := _similarity(anchor, line)) >= FUZZY_ANCHOR_MIN_SIMILARITY
    ]


def _numeric_anchor_pattern(
    anchor: str,
) -> tuple[re.Pattern[str], tuple[str, ...]] | None:
    token_matches = list(STABLE_VALUE_PATTERN.finditer(anchor))
    if not token_matches:
        return None

    pattern_parts: list[str] = []
    anchor_tokens: list[str] = []
    preceding_end = 0
    for token_match in token_matches:
        pattern_parts.append(re.escape(anchor[preceding_end : token_match.start()]))
        pattern_parts.append(f"({STABLE_VALUE_PATTERN.pattern})")
        anchor_tokens.append(token_match.group())
        preceding_end = token_match.end()
    pattern_parts.append(re.escape(anchor[preceding_end:]))
    return re.compile("".join(pattern_parts)), tuple(anchor_tokens)


def _numeric_token_shape(value: str) -> str:
    return "".join("#" if character.isdecimal() else character for character in value)


def _has_one_compatible_numeric_edit(
    anchor_tokens: tuple[str, ...], candidate_tokens: tuple[str, ...]
) -> bool:
    changed_tokens = [
        (anchor_token, candidate_token)
        for anchor_token, candidate_token in zip(anchor_tokens, candidate_tokens, strict=True)
        if anchor_token != candidate_token
    ]
    return len(changed_tokens) == 1 and (
        _numeric_token_shape(changed_tokens[0][0]) == _numeric_token_shape(changed_tokens[0][1])
    )


def _stable_anchor_occurrences(clause: ContractClause, selector: ClauseSelector) -> int | None:
    anchor = normalize_text(selector.anchor)
    clause_text = normalize_text(clause.text)
    if (
        not _has_sufficient_nonnumeric_context(anchor)
        or len(anchor) > MAX_FUZZY_ANCHOR_CHARACTERS
        or len(clause_text) > MAX_FUZZY_CLAUSE_CHARACTERS
    ):
        return 0
    numeric_anchor = _numeric_anchor_pattern(anchor)
    if numeric_anchor is None:
        return 0
    anchor_pattern, anchor_tokens = numeric_anchor
    matches = list(anchor_pattern.finditer(clause_text))
    if not matches:
        return 0
    compatible_edits = 0
    for match in matches:
        candidate_tokens = tuple(match.group(index) for index in range(1, len(anchor_tokens) + 1))
        if candidate_tokens == anchor_tokens:
            continue
        if not _has_one_compatible_numeric_edit(anchor_tokens, candidate_tokens):
            return None
        compatible_edits += 1
    return compatible_edits


def _candidate_anchor_fingerprint_score(clause: ContractClause, selector: ClauseSelector) -> float:
    fingerprint_matches = bool(selector.baseline_fingerprint) and (
        clause.fingerprint == selector.baseline_fingerprint
    )
    exact_occurrences = _anchor_occurrences(clause, selector)
    if STABLE_VALUE_PATTERN.search(normalize_text(selector.anchor)):
        stable_occurrences = _stable_anchor_occurrences(clause, selector)
        anchor_score = (
            0.0
            if stable_occurrences is None
            else float(exact_occurrences + stable_occurrences == selector.occurrences)
        )
    elif exact_occurrences:
        anchor_score = float(exact_occurrences == selector.occurrences)
    else:
        fuzzy_scores = _fuzzy_anchor_scores(clause, selector)
        anchor_score = min(fuzzy_scores) if len(fuzzy_scores) == selector.occurrences else 0.0
    return max(float(fingerprint_matches), anchor_score)


def _candidate_score(clause: ContractClause, selector: ClauseSelector) -> float:
    label_score = _similarity(selector.clause_label, clause.label.normalized)
    heading_score = _similarity(selector.heading, clause.heading)
    ancestor_score = float(
        _normalized_path(clause.ancestor_path) == _normalized_path(selector.ancestor_path)
    )
    anchor_or_fingerprint_score = _candidate_anchor_fingerprint_score(clause, selector)
    return fsum(
        (
            LABEL_WEIGHT * label_score,
            HEADING_WEIGHT * heading_score,
            ANCESTOR_WEIGHT * ancestor_score,
            ANCHOR_FINGERPRINT_WEIGHT * anchor_or_fingerprint_score,
        )
    )
