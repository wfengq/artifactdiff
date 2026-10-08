"""Shared value types for the evaluation harness."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

Language = Literal["en", "zh"]

VISUAL_UNAVAILABLE_RULE = "contract-safe.visual.unavailable"

_OUTCOME_RANK = {"pass": 0, "review": 1, "fail": 2}


class Expectation(StrEnum):
    ACCEPT = "accept"
    BLOCK = "block"


class Format(StrEnum):
    DOCX = "docx"
    PDF = "pdf"


@dataclass(frozen=True)
class AuthorizedEdit:
    before: str
    after: str
    paragraph_index: int
    clause_label: str
    heading: str
    anchor: str


@dataclass(frozen=True)
class SourceContract:
    source: str
    contract_id: str
    language: Language
    paragraphs: tuple[str, ...]
    declared_edit: AuthorizedEdit | None


@dataclass(frozen=True, order=True)
class CaseKey:
    source: str
    contract_id: str
    format: str
    operator: str


@dataclass(frozen=True)
class NotApplicable:
    reason: str


@dataclass(frozen=True)
class DraftFailure:
    source: str
    contract_id: str
    format: str
    reason: str


@dataclass(frozen=True)
class CaseResult:
    key: CaseKey
    expectation: Expectation
    text_verdict: str | None
    raw_outcome: str | None
    nonpass_rule_ids: tuple[str, ...]
    edited_clause_chars: int | None
    baseline_clause_count: int | None
    duration_s: float
    error: str | None

    @property
    def false_pass(self) -> bool:
        return self.expectation is Expectation.BLOCK and self.text_verdict == "pass"

    @property
    def accepted(self) -> bool:
        return self.expectation is Expectation.ACCEPT and self.text_verdict == "pass"

    def to_json(self) -> dict[str, object]:
        return {
            "key": {
                "source": self.key.source,
                "contract_id": self.key.contract_id,
                "format": self.key.format,
                "operator": self.key.operator,
            },
            "expectation": self.expectation.value,
            "text_verdict": self.text_verdict,
            "raw_outcome": self.raw_outcome,
            "nonpass_rule_ids": list(self.nonpass_rule_ids),
            "edited_clause_chars": self.edited_clause_chars,
            "baseline_clause_count": self.baseline_clause_count,
            "duration_s": self.duration_s,
            "error": self.error,
        }


def text_verdict(findings: Iterable[tuple[str, str]]) -> str:
    """Reduce findings to a verdict, ignoring the disabled visual layer."""
    worst = "pass"
    for rule_id, outcome in findings:
        if rule_id == VISUAL_UNAVAILABLE_RULE:
            continue
        if _OUTCOME_RANK[outcome] > _OUTCOME_RANK[worst]:
            worst = outcome
    return worst
