"""Bounded deterministic extraction of protected contract values."""

import hashlib
import re
from collections import Counter
from datetime import date
from decimal import Decimal, InvalidOperation

from artifactdiff.contract.models import EntityKind, EvidenceRef, ProtectedEntity

PARTY_PATTERN = re.compile(
    r"(?P<label>\u7532\u65b9|\u4e59\u65b9|\u4e19\u65b9|Party\s+[AB])\s*[:\uff1a]\s*(?P<value>[^;\uff1b\n\r]+)", re.I
)
ISO_DATE_PATTERN = re.compile(
    r"(?<!\d)(?P<year>\d{4})[-/.](?P<month>\d{1,2})[-/.](?P<day>\d{1,2})(?!\d)"
)
CHINESE_DATE_PATTERN = re.compile(
    r"(?<!\d)(?P<year>\d{4})\u5e74\s*(?P<month>\d{1,2})\u6708\s*(?P<day>\d{1,2})\u65e5(?!\d)"
)
CURRENCY_TOKEN = r"(?<![A-Za-z])(?:RMB|CNY|USD|EUR)(?![A-Za-z])|[\u00a5\uffe5$\u20ac]"
CURRENCY_PATTERN = re.compile(CURRENCY_TOKEN, re.I)
AMOUNT = r"[+-]?\d+(?:,\d{3})*(?:\.\d+)?"
MONEY_PREFIX_PATTERN = re.compile(
    rf"(?P<currency>{CURRENCY_TOKEN})\s*(?P<amount>{AMOUNT})", re.I
)
MONEY_SUFFIX_PATTERN = re.compile(
    rf"(?P<amount>{AMOUNT})\s*(?P<currency>{CURRENCY_TOKEN})", re.I
)
DURATION_PATTERN = re.compile(
    r"(?<!\d)(?P<amount>\d+(?:\.\d+)?)\s*(?P<unit>\u5929|\u65e5|\u4e2a\u6708|\u6708|\u5e74|days?|months?|years?)(?![A-Za-z\u4e00-\u9fff])",
    re.I,
)
PERCENTAGE_PATTERN = re.compile(r"(?<!\d)(?P<amount>\d+(?:\.\d+)?)\s*%(?!\d)")

CURRENCY_VALUES = {
    "RMB": "CNY",
    "CNY": "CNY",
    "\u00a5": "CNY",
    "\uffe5": "CNY",
    "USD": "USD",
    "$": "USD",
    "EUR": "EUR",
    "\u20ac": "EUR",
}
DURATION_UNITS = {
    "\u5929": "day",
    "\u65e5": "day",
    "day": "day",
    "days": "day",
    "\u4e2a\u6708": "month",
    "\u6708": "month",
    "month": "month",
    "months": "month",
    "\u5e74": "year",
    "year": "year",
    "years": "year",
}


def _entity_id(
    kind: EntityKind,
    value: str,
    clause_id: str | None,
    block_id: str,
    duplicate_location: tuple[int, int] | None = None,
) -> str:
    if duplicate_location is None:
        identity = block_id
    else:
        block_index, occurrence_index = duplicate_location
        identity = f"duplicate\0{block_index}\0{occurrence_index}"
    material = f"{kind.value}\0{value}\0{clause_id or ''}\0{identity}".encode("utf-8")
    return f"entity-{hashlib.sha256(material).hexdigest()[:24]}"


def _decimal_value(value: str) -> str | None:
    try:
        return format(Decimal(value.replace(",", "")), "f")
    except InvalidOperation:
        return None


def _date_value(match: re.Match[str]) -> str | None:
    try:
        return date(
            int(match.group("year")), int(match.group("month")), int(match.group("day"))
        ).isoformat()
    except ValueError:
        return None


def _currency_value(value: str) -> str:
    return CURRENCY_VALUES[value.upper()]


def extract_entities(
    text: str,
    clause_id: str | None,
    evidence: EvidenceRef,
    *,
    block_index: int = 0,
) -> list[ProtectedEntity]:
    """Extract only explicitly bounded protected values from one source block."""
    matches: list[tuple[int, EntityKind, str, str]] = []

    for match in PARTY_PATTERN.finditer(text):
        value = match.group("value").strip()
        if value:
            matches.append((match.start(), EntityKind.PARTY, match.group(), value))
    for pattern in (ISO_DATE_PATTERN, CHINESE_DATE_PATTERN):
        for match in pattern.finditer(text):
            value = _date_value(match)
            if value is not None:
                matches.append((match.start(), EntityKind.DATE, match.group(), value))
    for match in CURRENCY_PATTERN.finditer(text):
        matches.append((match.start(), EntityKind.CURRENCY, match.group(), _currency_value(match.group())))
    for pattern in (MONEY_PREFIX_PATTERN, MONEY_SUFFIX_PATTERN):
        for match in pattern.finditer(text):
            value = _decimal_value(match.group("amount"))
            if value is not None:
                matches.append((match.start(), EntityKind.MONEY, match.group(), value))
    for match in DURATION_PATTERN.finditer(text):
        amount = _decimal_value(match.group("amount"))
        if amount is not None:
            matches.append(
                (
                    match.start(),
                    EntityKind.DURATION,
                    match.group(),
                    f"{amount} {DURATION_UNITS[match.group('unit').casefold()]}",
                )
            )
    for match in PERCENTAGE_PATTERN.finditer(text):
        value = _decimal_value(match.group("amount"))
        if value is not None:
            matches.append((match.start(), EntityKind.PERCENTAGE, match.group(), value))

    matches.sort(key=lambda item: (item[0], item[1].value))
    group_counts = Counter((kind, value) for _, kind, _, value in matches)
    occurrences: Counter[tuple[EntityKind, str]] = Counter()
    entities: list[ProtectedEntity] = []
    for _, kind, matched_text, value in matches:
        key = (kind, value)
        duplicate_location = None
        if group_counts[key] > 1:
            duplicate_location = (block_index, occurrences[key])
            occurrences[key] += 1
        entities.append(
            ProtectedEntity(
                id=_entity_id(
                    kind,
                    value,
                    clause_id,
                    evidence.block_id,
                    duplicate_location,
                ),
                kind=kind,
                text=matched_text,
                normalized_value=value,
                clause_id=clause_id,
                evidence=[evidence],
            )
        )
    return entities
