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
CURRENCY_TOKEN = (
    r"(?<![A-Za-z])(?:HK\$|US\$|RMB|CNY|USD|EUR|GBP|HKD|JPY|CHF|SGD|AUD|CAD)(?![A-Za-z])"
    r"|[\u00a5\uffe5$\u20ac\u00a3]"
)
CURRENCY_PATTERN = re.compile(CURRENCY_TOKEN, re.IGNORECASE)
AMOUNT = r"[+-]?\d+(?:,\d{3})*(?:\.\d+)?"
SCALE = r"(?:\s+(?P<scale>thousand|million|billion)\b)?"
MONEY_PREFIX_PATTERN = re.compile(
    rf"(?P<currency>{CURRENCY_TOKEN})\s*(?P<amount>{AMOUNT}){SCALE}", re.IGNORECASE
)
MONEY_SUFFIX_PATTERN = re.compile(
    rf"(?P<amount>{AMOUNT}){SCALE}\s*(?P<currency>{CURRENCY_TOKEN})", re.IGNORECASE
)
CHINESE_CURRENCY_UNIT = (
    r"(?P<unit>\u7f8e\u5143|\u6e2f\u5143|\u6e2f\u5e01|\u65e5\u5143|\u6b27\u5143"
    r"|\u82f1\u9551|\u5143|\u5706)"
)
CHINESE_MONEY_PATTERN = re.compile(
    rf"(?:(?P<currency>\u4eba\u6c11\u5e01)\s*)?(?P<amount>{AMOUNT})\s*"
    rf"(?P<multiplier>\u4ebf|\u4e07)?{CHINESE_CURRENCY_UNIT}"
)
UPPERCASE_DIGITS = "\u96f6\u58f9\u8d30\u53c1\u8086\u4f0d\u9646\u67d2\u634c\u7396"
UPPERCASE_UNITS = "\u62fe\u4f70\u4edf\u4e07\u4ebf"
UPPERCASE_MONEY_PATTERN = re.compile(
    rf"(?:(?P<currency>\u4eba\u6c11\u5e01)\s*)?(?<![\d.])"
    rf"(?P<amount>[{UPPERCASE_DIGITS}\u62fe][{UPPERCASE_DIGITS}{UPPERCASE_UNITS}]*)"
    rf"(?P<unit>\u5143|\u5706)"
    rf"(?:(?P<jiao>[{UPPERCASE_DIGITS}])\u89d2)?(?:(?P<fen>[{UPPERCASE_DIGITS}])\u5206)?"
    r"(?:\u6574|\u6b63)?"
)
MONTH_NAMES = (
    r"(?P<month_name>January|February|March|April|May|June|July|August|September|October"
    r"|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sept|Sep|Oct|Nov|Dec)\.?"
)
ORDINAL_DAY = r"(?P<day>\d{1,2})(?:st|nd|rd|th)?"
ENGLISH_DATE_PATTERNS = (
    re.compile(
        rf"\b{MONTH_NAMES}\s+{ORDINAL_DAY},?\s+(?P<year>\d{{4}})(?!\d)", re.IGNORECASE
    ),
    re.compile(
        rf"(?<!\d){ORDINAL_DAY}\s+{MONTH_NAMES},?\s+(?P<year>\d{{4}})(?!\d)", re.IGNORECASE
    ),
)
DURATION_PATTERN = re.compile(
    r"(?<!\d)(?P<amount>\d+(?:\.\d+)?)[)\uff09]?\s*(?P<unit>\u5929|\u65e5|\u4e2a\u6708|\u6708|\u5e74|days?|months?|years?)"
    r"(?=$|[\s,.\uff0c\u3002\uff1b;\u3001:\uff1a)\uff09]|[\u5185\u524d\u540e\u8d77\u81f3])",
    re.IGNORECASE,
)
CHINESE_NUMERAL_CHARACTERS = (
    "\u96f6\u3007\u4e00\u4e8c\u4e24\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d"
    "\u5341\u767e\u5343\u4e07"
)
# Bare 日 and 月 after Chinese numerals usually name a calendar day or month, and
# 第/同/每/某/任/逐 before a numeral mark an ordinal or determiner, not a duration.
CHINESE_NUMERAL_DURATION_PATTERN = re.compile(
    rf"(?<![\u7b2c\u540c\u6bcf\u67d0\u4efb\u9010{CHINESE_NUMERAL_CHARACTERS}])"
    rf"(?P<amount>[{CHINESE_NUMERAL_CHARACTERS}]+)"
    r"(?:(?P<unit>\u5929|\u4e2a\u6708|\u5e74)|(?P<day_unit>\u65e5)(?=[\u5185\u524d\u540e\u8d77]))"
    r"(?![\u5ea6\u7ea7])"
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
    "\u58f9": 1,
    "\u8d30": 2,
    "\u53c1": 3,
    "\u8086": 4,
    "\u4f0d": 5,
    "\u9646": 6,
    "\u67d2": 7,
    "\u634c": 8,
    "\u7396": 9,
}
CHINESE_UNITS = {
    "\u5341": 10,
    "\u767e": 100,
    "\u5343": 1_000,
    "\u62fe": 10,
    "\u4f70": 100,
    "\u4edf": 1_000,
}
TEN_THOUSAND = "\u4e07"
HUNDRED_MILLION = "\u4ebf"
CHINESE_MONEY_MULTIPLIERS = {None: 1, "\u4e07": 10_000, "\u4ebf": 100_000_000}
CHINESE_CURRENCY_UNITS = {
    "\u5143": "CNY",
    "\u5706": "CNY",
    "\u7f8e\u5143": "USD",
    "\u6e2f\u5143": "HKD",
    "\u6e2f\u5e01": "HKD",
    "\u65e5\u5143": "JPY",
    "\u6b27\u5143": "EUR",
    "\u82f1\u9551": "GBP",
}
ENGLISH_SCALES = {None: 1, "thousand": 1_000, "million": 1_000_000, "billion": 1_000_000_000}
MONTHS = {
    name: index
    for index, names in enumerate(
        (
            ("january", "jan"),
            ("february", "feb"),
            ("march", "mar"),
            ("april", "apr"),
            ("may",),
            ("june", "jun"),
            ("july", "jul"),
            ("august", "aug"),
            ("september", "sept", "sep"),
            ("october", "oct"),
            ("november", "nov"),
            ("december", "dec"),
        ),
        start=1,
    )
    for name in names
}

CURRENCY_VALUES = {
    "RMB": "CNY",
    "CNY": "CNY",
    "\u00a5": "CNY",
    "\uffe5": "CNY",
    "USD": "USD",
    "$": "USD",
    "US$": "USD",
    "EUR": "EUR",
    "\u20ac": "EUR",
    "GBP": "GBP",
    "\u00a3": "GBP",
    "HKD": "HKD",
    "HK$": "HKD",
    "JPY": "JPY",
    "CHF": "CHF",
    "SGD": "SGD",
    "AUD": "AUD",
    "CAD": "CAD",
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
    material = f"{kind.value}\0{value}\0{clause_id or ''}\0{block_id}".encode()
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
    ten_thousands = 0
    section = 0
    digit: int | None = None
    previous = ""
    for index, character in enumerate(integer):
        if character in CHINESE_DIGITS:
            # Adjacent digits are only valid as a zero placeholder after a unit (一百零五);
            # sequences such as 二〇〇一 are year spellings, not quantities.
            if previous in CHINESE_DIGITS and not (
                CHINESE_DIGITS[previous] == 0
                and index >= 2
                and integer[index - 2] not in CHINESE_DIGITS
            ):
                return None
            digit = CHINESE_DIGITS[character]
        elif character in CHINESE_UNITS:
            section += (digit or 1) * CHINESE_UNITS[character]
            digit = None
        elif character == TEN_THOUSAND:
            ten_thousands += (section + (digit or 0)) * 10_000
            section = 0
            digit = None
        elif character == HUNDRED_MILLION:
            total = (total + ten_thousands + section + (digit or 0)) * 100_000_000
            ten_thousands = 0
            section = 0
            digit = None
        else:
            return None
        previous = character
    number = Decimal(total + ten_thousands + section + (digit or 0))
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


def _english_date_value(match: re.Match[str]) -> str | None:
    month = MONTHS[match.group("month_name").casefold()]
    try:
        return date(int(match.group("year")), month, int(match.group("day"))).isoformat()
    except ValueError:
        return None


def _uppercase_money_value(match: re.Match[str]) -> str | None:
    integer = _chinese_number_value(match.group("amount"))
    if integer is None:
        return None
    value = Decimal(integer)
    for group, scale in (("jiao", Decimal("0.1")), ("fen", Decimal("0.01"))):
        if match.group(group):
            value += CHINESE_DIGITS[match.group(group)] * scale
    return format(value, "f")


def _currency_value(value: str) -> str:
    return CURRENCY_VALUES[value.upper()]


def _chinese_currency(match: re.Match[str]) -> tuple[EntityKind, str, str]:
    unit = match.group("unit")
    currency = CHINESE_CURRENCY_UNITS[unit]
    prefix = match.group("currency")
    if prefix and currency == "CNY":
        return EntityKind.CURRENCY, prefix, currency
    return EntityKind.CURRENCY, unit, currency


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
    for pattern in ENGLISH_DATE_PATTERNS:
        for match in pattern.finditer(text):
            value = _english_date_value(match)
            if value is not None:
                matches.append((match.start(), EntityKind.DATE, match.group(), value))
                date_spans.append(match.span())
    for match in CURRENCY_PATTERN.finditer(text):
        matches.append((match.start(), EntityKind.CURRENCY, match.group(), _currency_value(match.group())))
    for pattern in (MONEY_PREFIX_PATTERN, MONEY_SUFFIX_PATTERN):
        for match in pattern.finditer(text):
            amount = _decimal_value(match.group("amount"))
            if amount is not None:
                scale = match.group("scale")
                value = Decimal(amount) * ENGLISH_SCALES[scale.casefold() if scale else None]
                matches.append((match.start(), EntityKind.MONEY, match.group(), format(value, "f")))
    for match in CHINESE_MONEY_PATTERN.finditer(text):
        amount = _decimal_value(match.group("amount"))
        if amount is not None:
            value = Decimal(amount) * CHINESE_MONEY_MULTIPLIERS[match.group("multiplier")]
            matches.append((match.start(), *_chinese_currency(match)))
            matches.append(
                (match.start(), EntityKind.MONEY, match.group(), format(value, "f"))
            )
    for match in UPPERCASE_MONEY_PATTERN.finditer(text):
        uppercase_value = _uppercase_money_value(match)
        if uppercase_value is not None:
            matches.append((match.start(), *_chinese_currency(match)))
            matches.append((match.start(), EntityKind.MONEY, match.group(), uppercase_value))
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
    for match in CHINESE_NUMERAL_DURATION_PATTERN.finditer(text):
        amount = _chinese_number_value(match.group("amount"))
        if amount is not None and amount != "0":
            unit = match.group("unit") or match.group("day_unit")
            matches.append(
                (
                    match.start(),
                    EntityKind.DURATION,
                    match.group(),
                    f"{amount} {DURATION_UNITS[unit]}",
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
