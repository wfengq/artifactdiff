"""Bounded deterministic extraction of protected contract values."""

import hashlib
import re
from collections import Counter
from datetime import date
from decimal import Decimal, InvalidOperation

from artifactdiff.contract.models import EntityKind, EvidenceRef, ProtectedEntity

PARTY_PATTERN = re.compile(
    r"(?P<label>\u7532\u65b9|\u4e59\u65b9|\u4e19\u65b9|Party\s+[AB])"
    r"(?:[\uff08(][^\uff09)\n\r]{1,20}[\uff09)])?\s*[:\uff1a]\s*"
    r"(?P<value>[^;\uff1b\n\r]+)",
    re.IGNORECASE,
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
CHINESE_MONEY_PATTERN = re.compile(
    rf"(?P<currency>\u4eba\u6c11\u5e01)\s*(?P<amount>{AMOUNT})\s*"
    r"(?P<unit>\u4ebf\u5143|\u4e07\u5143|\u5143)"
)
DURATION_PATTERN = re.compile(
    r"(?<!\d)(?P<amount>\d+(?:\.\d+)?)\s*(?P<unit>\u5929|\u65e5|\u4e2a\u6708|\u6708|\u5e74|days?|months?|years?)"
    r"(?=$|[\s,.\uff0c\u3002\uff1b;\u3001:\uff1a)\uff09]|[\u5185\u524d\u540e\u8d77\u81f3])",
    re.IGNORECASE,
)
PERCENTAGE_PATTERN = re.compile(r"(?<!\d)(?P<amount>\d+(?:\.\d+)?)\s*%(?!\d)")
CHINESE_PERCENTAGE_PATTERN = re.compile(
    r"\u767e\u5206\u4e4b(?P<amount>[\u96f6\u3007\u4e00\u4e8c\u4e24\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341\u767e\u5343\u4e07\u70b9]+)"
)

CHINESE_DIGITS = {
    "\u96f6": 0,
    "\u3007": 0,
    "\u4e00": 1,
    "\u4e8c": 2,
    "\u4e24": 2,
    "\u4e09": 3,
    "\u56db": 4,
    "\u4e94": 5,
    "\u516d": 6,
    "\u4e03": 7,
    "\u516b": 8,
    "\u4e5d": 9,
}
CHINESE_UNITS = {"\u5341": 10, "\u767e": 100, "\u5343": 1_000, "\u4e07": 10_000}
CHINESE_MONEY_MULTIPLIERS = {"\u5143": 1, "\u4e07\u5143": 10_000, "\u4ebf\u5143": 100_000_000}

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
) -> str:
    material = f"{kind.value}\0{value}\0{clause_id or ''}\0{block_id}".encode("utf-8")
    return f"entity-{hashlib.sha256(material).hexdigest()[:24]}"


def _duplicate_entity_id(
    kind: EntityKind,
    value: str,
    clause_id: str | None,
    occurrence_index: int,
) -> str:
    material = f"{kind.value}\0{value}\0{clause_id or ''}\0duplicate\0{occurrence_index}".encode()
    return f"entity-{hashlib.sha256(material).hexdigest()[:24]}"


def assign_clause_entity_ids(entities: list[ProtectedEntity]) -> list[ProtectedEntity]:
    """Assign segmentation-independent IDs to repeated clause entity groups."""
    group_counts = Counter((item.kind, item.normalized_value) for item in entities)
    occurrences: Counter[tuple[EntityKind, str]] = Counter()
    assigned: list[ProtectedEntity] = []
    for entity in entities:
        key = (entity.kind, entity.normalized_value)
        if group_counts[key] == 1:
            assigned.append(entity)
            continue
        occurrence_index = occurrences[key]
        occurrences[key] += 1
        assigned.append(
            entity.model_copy(
                update={
                    "id": _duplicate_entity_id(
                        entity.kind,
                        entity.normalized_value,
                        entity.clause_id,
                        occurrence_index,
                    )
                }
            )
        )
    return assigned


def _decimal_value(value: str) -> str | None:
    try:
        return format(Decimal(value.replace(",", "")), "f")
    except InvalidOperation:
        return None


def _chinese_number_value(value: str) -> str | None:
    integer, separator, fraction = value.partition("\u70b9")
    total = 0
    section = 0
    digit = 0
    for character in integer:
        if character in CHINESE_DIGITS:
            digit = CHINESE_DIGITS[character]
        elif character in CHINESE_UNITS:
            unit = CHINESE_UNITS[character]
            if unit == 10_000:
                total += (section + digit) * unit
                section = 0
            else:
                section += (digit or 1) * unit
            digit = 0
        else:
            return None
    number = Decimal(total + section + digit)
    if separator:
        if not fraction or any(character not in CHINESE_DIGITS for character in fraction):
            return None
        fraction_text = "".join(str(CHINESE_DIGITS[character]) for character in fraction)
        number += Decimal(f"0.{fraction_text}")
    return format(number, "f")


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
) -> list[ProtectedEntity]:
    """Extract only explicitly bounded protected values from one source block."""
    matches: list[tuple[int, EntityKind, str, str]] = []
    date_spans: list[tuple[int, int]] = []

    for match in PARTY_PATTERN.finditer(text):
        value = match.group("value").strip()
        if value:
            matches.append((match.start(), EntityKind.PARTY, match.group(), value))
    for pattern in (ISO_DATE_PATTERN, CHINESE_DATE_PATTERN):
        for match in pattern.finditer(text):
            value = _date_value(match)
            if value is not None:
                matches.append((match.start(), EntityKind.DATE, match.group(), value))
                date_spans.append(match.span())
    for match in CURRENCY_PATTERN.finditer(text):
        matches.append((match.start(), EntityKind.CURRENCY, match.group(), _currency_value(match.group())))
    for pattern in (MONEY_PREFIX_PATTERN, MONEY_SUFFIX_PATTERN):
        for match in pattern.finditer(text):
            value = _decimal_value(match.group("amount"))
            if value is not None:
                matches.append((match.start(), EntityKind.MONEY, match.group(), value))
    for match in CHINESE_MONEY_PATTERN.finditer(text):
        amount = _decimal_value(match.group("amount"))
        if amount is not None:
            value = Decimal(amount) * CHINESE_MONEY_MULTIPLIERS[match.group("unit")]
            matches.append((match.start(), EntityKind.CURRENCY, match.group("currency"), "CNY"))
            matches.append((match.start(), EntityKind.MONEY, match.group(), format(value, "f")))
    for match in DURATION_PATTERN.finditer(text):
        if any(match.start() < end and start < match.end() for start, end in date_spans):
            continue
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
    for match in CHINESE_PERCENTAGE_PATTERN.finditer(text):
        value = _chinese_number_value(match.group("amount"))
        if value is not None:
            matches.append((match.start(), EntityKind.PERCENTAGE, match.group(), value))

    matches.sort(key=lambda item: (item[0], item[1].value))
    entities: list[ProtectedEntity] = []
    for _, kind, matched_text, value in matches:
        entities.append(
            ProtectedEntity(
                id=_entity_id(kind, value, clause_id, evidence.block_id),
                kind=kind,
                text=matched_text,
                normalized_value=value,
                clause_id=clause_id,
                evidence=[evidence],
            )
        )
    return assign_clause_entity_ids(entities)
