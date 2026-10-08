"""Mutation operators that derive candidate contracts with known expectations.

The harness owns every pattern here and deliberately does not reuse ArtifactDiff's
entity extractor, so the benchmark is not limited to values the tool already knows.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, timedelta

from evaluation.models import AuthorizedEdit, Expectation, Language, NotApplicable

Paragraphs = tuple[str, ...]
Result = Paragraphs | NotApplicable
Operator = Callable[[Paragraphs, AuthorizedEdit, Language, random.Random], Result]


@dataclass(frozen=True)
class OperatorSpec:
    name: str
    group: str
    expectation: Expectation
    fn: Operator


_NUMBER = re.compile(r"\d+")
_MONEY = re.compile(
    r"(?:\$|USD|RMB|人民币)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:dollars|万元|元)"
)
_DURATION = re.compile(r"\d+\s?(?:days?|months?|years?|个月|天|日|年)")
_PERCENTAGE = re.compile(r"\d+(?:\.\d+)?\s?(?:%|percent)")
_MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
_ISO_DATE = re.compile(r"(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})")
_ZH_DATE = re.compile(r"(?P<year>\d{4})年(?P<month>\d{1,2})月(?P<day>\d{1,2})日")
_EN_DATE = re.compile(rf"(?P<month_name>{'|'.join(_MONTHS)}) (?P<day>\d{{1,2}}), (?P<year>\d{{4}})")
_EN_PARTY = re.compile(r"(?P<name>(?:[A-Z][\w&.-]*\s){1,4})(?P<suffix>Inc\.|LLC|Ltd\.|Corporation)")
_ZH_PARTY = re.compile(r"(?:甲方|乙方)：(?P<name>[^；;。\n]+)")
# A capitalized word such as a defined term ("Affiliate"); case carries legal meaning.
_CAPITALIZED = re.compile(r"\b[A-Z][a-z]{3,}\b")


@dataclass(frozen=True)
class _LanguageTable:
    unit_from: str
    unit_to: str
    negation_site: re.Pattern[str]
    negation_insert: str
    negation_remove_site: re.Pattern[str]
    negation_remove: str
    modal_site: re.Pattern[str]
    modal_swap: str
    inserted_sentence: str
    party: re.Pattern[str]


_TABLES: dict[Language, _LanguageTable] = {
    "en": _LanguageTable(
        unit_from="days",
        unit_to="business days",
        negation_site=re.compile(r"\bshall\b(?!\s+not\b)"),
        negation_insert="shall not",
        negation_remove_site=re.compile(r"\bshall not\b"),
        negation_remove="shall",
        modal_site=re.compile(r"\bmay\b"),
        modal_swap="shall",
        inserted_sentence=" The Supplier shall bear all related costs.",
        party=_EN_PARTY,
    ),
    "zh": _LanguageTable(
        unit_from="天",
        unit_to="个工作日",
        negation_site=re.compile(r"(?<![不供相对反响适])应"),
        negation_insert="不应",
        negation_remove_site=re.compile(r"不得"),
        negation_remove="可以",
        modal_site=re.compile(r"可以"),
        modal_swap="应当",
        inserted_sentence="供方应承担全部相关费用。",
        party=_ZH_PARTY,
    ),
}


def operator_rng(seed: int, contract_id: str, operator: str) -> random.Random:
    material = f"{seed}\0{contract_id}\0{operator}".encode()
    return random.Random(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))


def apply_authorized(paragraphs: Paragraphs, edit: AuthorizedEdit) -> Paragraphs:
    return _replace_paragraph(
        paragraphs,
        edit.paragraph_index,
        paragraphs[edit.paragraph_index].replace(edit.before, edit.after, 1),
    )


def _replace_paragraph(paragraphs: Paragraphs, index: int, text: str) -> Paragraphs:
    return tuple(text if i == index else value for i, value in enumerate(paragraphs))


def _increment_first_number(token: str) -> str:
    return _NUMBER.sub(lambda match: str(int(match.group()) + 1), token, count=1)


def _sentences(text: str, language: Language) -> list[str]:
    if language == "zh":
        return re.findall(r"[^。；]*[。；]|[^。；]+$", text)
    return re.split(r"(?<=[.;])\s+", text.strip())


def _join(sentences: list[str], language: Language) -> str:
    return ("" if language == "zh" else " ").join(sentences)


def _date_spans(text: str) -> list[tuple[int, int]]:
    return [m.span() for p in (_ISO_DATE, _ZH_DATE, _EN_DATE) for m in p.finditer(text)]


def _first_match(
    pattern: re.Pattern[str], text: str, *, avoid_dates: bool = False
) -> re.Match[str] | None:
    spans = _date_spans(text) if avoid_dates else []
    for match in pattern.finditer(text):
        if not any(match.start() < end and start < match.end() for start, end in spans):
            return match
    return None


def _elsewhere(
    paragraphs: Paragraphs,
    edit: AuthorizedEdit,
    rng: random.Random,
    applicable: Callable[[str], bool],
    reason: str,
) -> int | NotApplicable:
    sites = sorted(
        index
        for index, text in enumerate(paragraphs)
        if index != edit.paragraph_index and applicable(text)
    )
    if not sites:
        return NotApplicable(reason)
    return rng.choice(sites)


def _token_change(
    pattern: re.Pattern[str],
    reason: str,
    change: Callable[[re.Match[str]], str],
    *,
    avoid_dates: bool = False,
) -> Operator:
    def operator(
        paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
    ) -> Result:
        candidate = apply_authorized(paragraphs, edit)
        site = _elsewhere(
            candidate,
            edit,
            rng,
            lambda text: _first_match(pattern, text, avoid_dates=avoid_dates) is not None,
            reason,
        )
        if isinstance(site, NotApplicable):
            return site
        text = candidate[site]
        match = _first_match(pattern, text, avoid_dates=avoid_dates)
        assert match is not None
        return _replace_paragraph(
            candidate, site, text[: match.start()] + change(match) + text[match.end() :]
        )

    return operator


def _shift_date(match: re.Match[str]) -> str:
    groups = match.groupdict()
    if "month_name" in groups and groups["month_name"]:
        month = _MONTHS.index(groups["month_name"]) + 1
    else:
        month = int(groups["month"])
    try:
        original = date(int(groups["year"]), month, int(groups["day"]))
    except ValueError:
        return _increment_first_number(match.group())
    shifted = original + timedelta(days=1)
    if shifted.month != original.month:
        shifted = original - timedelta(days=1)
    start, end = match.span("day")
    offset = match.start()
    text = match.group()
    day = str(shifted.day).zfill(end - start)
    return text[: start - offset] + day + text[end - offset :]


def _date_change(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)

    def first_date(text: str) -> re.Match[str] | None:
        found = [m for p in (_ISO_DATE, _ZH_DATE, _EN_DATE) for m in p.finditer(text)]
        return min(found, key=lambda m: m.start()) if found else None

    site = _elsewhere(candidate, edit, rng, lambda t: first_date(t) is not None, "no date site")
    if isinstance(site, NotApplicable):
        return site
    text = candidate[site]
    match = first_date(text)
    assert match is not None
    return _replace_paragraph(
        candidate, site, text[: match.start()] + _shift_date(match) + text[match.end() :]
    )


def _party_change(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    pattern = _TABLES[language].party
    candidate = apply_authorized(paragraphs, edit)
    site = _elsewhere(candidate, edit, rng, lambda t: pattern.search(t) is not None, "no party")
    if isinstance(site, NotApplicable):
        return site
    text = candidate[site]
    match = pattern.search(text)
    assert match is not None
    if language == "zh":
        start, end = match.span("name")
        changed = text[:end] + "控股" + text[end:]
    else:
        start = match.start("suffix")
        changed = text[:start] + "Holdings " + text[start:]
    return _replace_paragraph(candidate, site, changed)


def _substitution(site_attr: str, replacement_attr: str, reason: str) -> Operator:
    def operator(
        paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
    ) -> Result:
        table = _TABLES[language]
        pattern: re.Pattern[str] = getattr(table, site_attr)
        replacement: str = getattr(table, replacement_attr)
        candidate = apply_authorized(paragraphs, edit)
        site = _elsewhere(candidate, edit, rng, lambda t: pattern.search(t) is not None, reason)
        if isinstance(site, NotApplicable):
            return site
        return _replace_paragraph(
            candidate, site, pattern.sub(replacement, candidate[site], count=1)
        )

    return operator


def _authorized(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    return apply_authorized(paragraphs, edit)


def _missing_edit(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    return paragraphs


def _wrong_value(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    wrong = _increment_first_number(edit.after)
    if wrong == edit.after:
        return NotApplicable("authorized value has no number")
    text = paragraphs[edit.paragraph_index].replace(edit.before, wrong, 1)
    return _replace_paragraph(paragraphs, edit.paragraph_index, text)


def _unit_change(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    table = _TABLES[language]
    if table.unit_from not in edit.after:
        return NotApplicable(f"authorized value has no '{table.unit_from}' unit")
    wrong = edit.after.replace(table.unit_from, table.unit_to, 1)
    text = paragraphs[edit.paragraph_index].replace(edit.before, wrong, 1)
    return _replace_paragraph(paragraphs, edit.paragraph_index, text)


def _same_para_number(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    text = candidate[edit.paragraph_index]
    start = text.find(edit.after)
    protected = (start, start + len(edit.after))
    for match in _NUMBER.finditer(text):
        if protected[0] <= match.start() < protected[1]:
            continue
        changed = text[: match.start()] + str(int(match.group()) + 1) + text[match.end() :]
        return _replace_paragraph(candidate, edit.paragraph_index, changed)
    return NotApplicable("no other number in edited paragraph")


def _same_para_negation(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    table = _TABLES[language]
    candidate = apply_authorized(paragraphs, edit)
    text = candidate[edit.paragraph_index]
    if not table.negation_site.search(text):
        return NotApplicable("no modal in edited paragraph")
    changed = table.negation_site.sub(table.negation_insert, text, count=1)
    return _replace_paragraph(candidate, edit.paragraph_index, changed)


def _same_para_sentence_delete(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    sentences = _sentences(candidate[edit.paragraph_index], language)
    for index, sentence in enumerate(sentences):
        if edit.after not in sentence and len(sentences) >= 2:
            remaining = sentences[:index] + sentences[index + 1 :]
            return _replace_paragraph(candidate, edit.paragraph_index, _join(remaining, language))
    return NotApplicable("edited paragraph has no other sentence")


def _same_para_case_change(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    text = candidate[edit.paragraph_index]
    start = text.find(edit.after)
    protected = (start, start + len(edit.after))
    for match in _CAPITALIZED.finditer(text):
        if match.start() < protected[1] and protected[0] < match.end():
            continue
        changed = text[: match.start()] + match.group().lower() + text[match.end() :]
        return _replace_paragraph(candidate, edit.paragraph_index, changed)
    return NotApplicable("no capitalized word in edited paragraph")


def _case_change(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    site = _elsewhere(
        candidate, edit, rng, lambda t: _CAPITALIZED.search(t) is not None, "no capitalized word"
    )
    if isinstance(site, NotApplicable):
        return site
    text = candidate[site]
    match = _CAPITALIZED.search(text)
    assert match is not None
    changed = text[: match.start()] + match.group().lower() + text[match.end() :]
    return _replace_paragraph(candidate, site, changed)


def _whitespace_noise(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    site = _elsewhere(candidate, edit, rng, lambda t: " " in t, "no space to widen")
    if isinstance(site, NotApplicable):
        return site
    return _replace_paragraph(candidate, site, candidate[site].replace(" ", "  ", 1))


def _sentence_insert(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    site = _elsewhere(candidate, edit, rng, lambda t: bool(t.strip()), "no other paragraph")
    if isinstance(site, NotApplicable):
        return site
    text = candidate[site] + _TABLES[language].inserted_sentence
    return _replace_paragraph(candidate, site, text)


def _sentence_delete(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    site = _elsewhere(
        candidate,
        edit,
        rng,
        lambda t: len(_sentences(t, language)) >= 2,
        "no multi-sentence paragraph",
    )
    if isinstance(site, NotApplicable):
        return site
    sentences = _sentences(candidate[site], language)
    return _replace_paragraph(candidate, site, _join(sentences[:-1], language))


def _paragraph_delete(
    paragraphs: Paragraphs, edit: AuthorizedEdit, language: Language, rng: random.Random
) -> Result:
    candidate = apply_authorized(paragraphs, edit)
    site = _elsewhere(candidate, edit, rng, lambda t: True, "no other paragraph")
    if isinstance(site, NotApplicable):
        return site
    return candidate[:site] + candidate[site + 1 :]


_BLOCK = Expectation.BLOCK
OPERATORS: tuple[OperatorSpec, ...] = (
    OperatorSpec("authorized", "baseline", Expectation.ACCEPT, _authorized),
    OperatorSpec("missing_edit", "application", _BLOCK, _missing_edit),
    OperatorSpec("wrong_value", "application", _BLOCK, _wrong_value),
    OperatorSpec("unit_change", "application", _BLOCK, _unit_change),
    OperatorSpec("same_para_number", "same paragraph", _BLOCK, _same_para_number),
    OperatorSpec("same_para_negation", "same paragraph", _BLOCK, _same_para_negation),
    OperatorSpec(
        "same_para_sentence_delete", "same paragraph", _BLOCK, _same_para_sentence_delete
    ),
    OperatorSpec("same_para_case_change", "same paragraph", _BLOCK, _same_para_case_change),
    OperatorSpec(
        "money_change",
        "elsewhere",
        _BLOCK,
        _token_change(_MONEY, "no money site", lambda m: _increment_first_number(m.group())),
    ),
    OperatorSpec("date_change", "elsewhere", _BLOCK, _date_change),
    OperatorSpec(
        "duration_change",
        "elsewhere",
        _BLOCK,
        _token_change(
            _DURATION,
            "no duration site",
            lambda m: _increment_first_number(m.group()),
            avoid_dates=True,
        ),
    ),
    OperatorSpec(
        "percentage_change",
        "elsewhere",
        _BLOCK,
        _token_change(
            _PERCENTAGE, "no percentage site", lambda m: _increment_first_number(m.group())
        ),
    ),
    OperatorSpec("party_change", "elsewhere", _BLOCK, _party_change),
    OperatorSpec(
        "negation_insert",
        "elsewhere",
        _BLOCK,
        _substitution("negation_site", "negation_insert", "no modal site"),
    ),
    OperatorSpec(
        "negation_remove",
        "elsewhere",
        _BLOCK,
        _substitution("negation_remove_site", "negation_remove", "no negation site"),
    ),
    OperatorSpec(
        "modal_swap", "elsewhere", _BLOCK, _substitution("modal_site", "modal_swap", "no may site")
    ),
    OperatorSpec("sentence_insert", "elsewhere", _BLOCK, _sentence_insert),
    OperatorSpec("sentence_delete", "elsewhere", _BLOCK, _sentence_delete),
    OperatorSpec("paragraph_delete", "elsewhere", _BLOCK, _paragraph_delete),
    OperatorSpec("case_change", "elsewhere", _BLOCK, _case_change),
    # Whitespace-only noise must not block: PDF reflow and editors change spacing freely.
    OperatorSpec("whitespace_noise", "robustness", Expectation.ACCEPT, _whitespace_noise),
)
