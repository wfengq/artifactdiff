import random

import pytest

from evaluation.models import AuthorizedEdit, Expectation, NotApplicable
from evaluation.mutations import OPERATORS, OperatorSpec, apply_authorized, operator_rng

EN = (
    "Acme Analytics Inc. and Northwind Ltd. sign on 2026-08-04. The Customer may audit records.",
    "The Customer shall pay within 30 days of receipt. Each invoice may list 12 items.",
    "The fee is USD 12,500.00 and late interest is 1.5% per month. The Provider shall not disclose data.",
    "This agreement lasts 24 months. The Provider shall keep records.",
)
EN_EDIT = AuthorizedEdit("30 days", "45 days", 1, "", "", "within")
ZH = (
    "甲方：上海示例科技有限公司；乙方：北京样例贸易有限公司。本合同于2026年8月4日签订。",
    "甲方应于验收后30天内付款。每期发票最多包含12个项目。",
    "服务费为人民币120,000元，逾期按0.5%计息。乙方不得披露保密信息。",
    "本合同有效期为24个月。乙方应保存记录。双方可以协商。",
)
ZH_EDIT = AuthorizedEdit("30天", "45天", 1, "", "", "验收后")
EN_AUTH = apply_authorized(EN, EN_EDIT)
ZH_AUTH = apply_authorized(ZH, ZH_EDIT)


def op(name: str) -> OperatorSpec:
    return next(spec for spec in OPERATORS if spec.name == name)


def run(name: str, language: str = "en") -> tuple[str, ...]:
    paragraphs, edit = (EN, EN_EDIT) if language == "en" else (ZH, ZH_EDIT)
    result = op(name).fn(paragraphs, edit, language, operator_rng(0, "fixture", name))  # type: ignore[arg-type]
    assert not isinstance(result, NotApplicable), result
    return result


def replaced(base: tuple[str, ...], index: int, old: str, new: str) -> tuple[str, ...]:
    assert base[index].count(old) == 1
    return tuple(text.replace(old, new) if i == index else text for i, text in enumerate(base))


def test_operator_table_matches_spec() -> None:
    assert [spec.name for spec in OPERATORS] == [
        "authorized",
        "missing_edit",
        "wrong_value",
        "unit_change",
        "same_para_number",
        "same_para_negation",
        "same_para_sentence_delete",
        "same_para_case_change",
        "money_change",
        "date_change",
        "duration_change",
        "percentage_change",
        "party_change",
        "negation_insert",
        "negation_remove",
        "modal_swap",
        "sentence_insert",
        "sentence_delete",
        "paragraph_delete",
        "case_change",
        "whitespace_noise",
    ]
    assert [s.name for s in OPERATORS if s.expectation is Expectation.ACCEPT] == [
        "authorized",
        "whitespace_noise",
    ]
    assert {s.group for s in OPERATORS} == {
        "baseline",
        "application",
        "same paragraph",
        "elsewhere",
        "robustness",
    }


def test_apply_authorized_changes_only_the_edited_paragraph() -> None:
    assert EN_AUTH == replaced(EN, 1, "30 days", "45 days")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("authorized", EN_AUTH),
        ("missing_edit", EN),
        ("wrong_value", replaced(EN, 1, "30 days", "46 days")),
        ("unit_change", replaced(EN_AUTH, 1, "45 days", "45 business days")),
        ("same_para_number", replaced(EN_AUTH, 1, "12 items", "13 items")),
        ("same_para_negation", replaced(EN_AUTH, 1, "shall pay", "shall not pay")),
        ("same_para_sentence_delete", replaced(EN_AUTH, 1, " Each invoice may list 12 items.", "")),
        ("money_change", replaced(EN_AUTH, 2, "USD 12,500.00", "USD 13,500.00")),
        ("date_change", replaced(EN_AUTH, 0, "2026-08-04", "2026-08-05")),
        ("duration_change", replaced(EN_AUTH, 3, "24 months", "25 months")),
        ("percentage_change", replaced(EN_AUTH, 2, "1.5%", "2.5%")),
        ("party_change", replaced(EN_AUTH, 0, "Acme Analytics Inc.", "Acme Analytics Holdings Inc.")),
        ("negation_insert", replaced(EN_AUTH, 3, "shall keep", "shall not keep")),
        ("negation_remove", replaced(EN_AUTH, 2, "shall not disclose", "shall disclose")),
        ("modal_swap", replaced(EN_AUTH, 0, "may audit", "shall audit")),
        ("same_para_case_change", replaced(EN_AUTH, 1, "The Customer shall", "The customer shall")),
    ],
)
def test_english_operators_make_exact_changes(name: str, expected: tuple[str, ...]) -> None:
    assert run(name, "en") == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("wrong_value", replaced(ZH, 1, "30天", "46天")),
        ("unit_change", replaced(ZH_AUTH, 1, "45天", "45个工作日")),
        ("same_para_number", replaced(ZH_AUTH, 1, "12个", "13个")),
        ("same_para_negation", replaced(ZH_AUTH, 1, "甲方应于", "甲方不应于")),
        ("same_para_sentence_delete", replaced(ZH_AUTH, 1, "每期发票最多包含12个项目。", "")),
        ("money_change", replaced(ZH_AUTH, 2, "人民币120,000", "人民币121,000")),
        ("date_change", replaced(ZH_AUTH, 0, "2026年8月4日", "2026年8月5日")),
        ("duration_change", replaced(ZH_AUTH, 3, "24个月", "25个月")),
        ("percentage_change", replaced(ZH_AUTH, 2, "0.5%", "1.5%")),
        ("party_change", replaced(ZH_AUTH, 0, "上海示例科技有限公司", "上海示例科技有限公司控股")),
        ("negation_insert", replaced(ZH_AUTH, 3, "乙方应保存", "乙方不应保存")),
        ("negation_remove", replaced(ZH_AUTH, 2, "不得", "可以")),
        ("modal_swap", replaced(ZH_AUTH, 3, "可以", "应当")),
    ],
)
def test_chinese_operators_make_exact_changes(name: str, expected: tuple[str, ...]) -> None:
    assert run(name, "zh") == expected


def test_english_month_name_date_changes_day() -> None:
    paragraphs = ("Signed on August 31, 2026.", "Pay within 30 days.")
    edit = AuthorizedEdit("30 days", "45 days", 1, "", "", "within")
    result = op("date_change").fn(paragraphs, edit, "en", random.Random(0))
    assert result == ("Signed on August 30, 2026.", "Pay within 45 days.")


def test_negation_insert_zh_skips_existing_bu_ying() -> None:
    paragraphs = ("乙方不应迟延。乙方应保存记录。", "甲方应于30天内付款。")
    edit = AuthorizedEdit("30天", "45天", 1, "", "", "应于")
    result = op("negation_insert").fn(paragraphs, edit, "zh", random.Random(0))
    assert result == ("乙方不应迟延。乙方不应保存记录。", "甲方应于45天内付款。")


@pytest.mark.parametrize("language", ["en", "zh"])
def test_structural_elsewhere_operators_touch_one_other_paragraph(language: str) -> None:
    base = EN_AUTH if language == "en" else ZH_AUTH
    inserted = run("sentence_insert", language)
    changed = [i for i, (a, b) in enumerate(zip(base, inserted, strict=True)) if a != b]
    assert len(changed) == 1 and changed[0] != 1
    assert len(inserted[changed[0]]) > len(base[changed[0]])

    deleted = run("sentence_delete", language)
    changed = [i for i, (a, b) in enumerate(zip(base, deleted, strict=True)) if a != b]
    assert len(changed) == 1 and changed[0] != 1
    assert base[changed[0]].startswith(deleted[changed[0]].rstrip())

    dropped = run("paragraph_delete", language)
    assert len(dropped) == len(base) - 1
    assert base[1] in dropped


def test_every_operator_is_deterministic_for_same_seed() -> None:
    for spec in OPERATORS:
        for language, paragraphs, edit in (("en", EN, EN_EDIT), ("zh", ZH, ZH_EDIT)):
            first = spec.fn(paragraphs, edit, language, operator_rng(0, "c", spec.name))  # type: ignore[arg-type]
            second = spec.fn(paragraphs, edit, language, operator_rng(0, "c", spec.name))  # type: ignore[arg-type]
            assert first == second


def test_operator_rng_depends_on_all_inputs() -> None:
    draws = {
        operator_rng(seed, contract, name).random()
        for seed, contract, name in ((0, "a", "x"), (1, "a", "x"), (0, "b", "x"), (0, "a", "y"))
    }
    assert len(draws) == 4


def test_operators_return_not_applicable_without_a_site() -> None:
    paragraphs = ("Plain heading", "Pay within 30 days.")
    edit = AuthorizedEdit("30 days", "45 days", 1, "", "", "within")
    for name in ("money_change", "date_change", "party_change", "negation_remove", "same_para_number"):
        result = op(name).fn(paragraphs, edit, "en", random.Random(0))
        assert isinstance(result, NotApplicable), name


def test_case_change_lowercases_one_capitalized_word_elsewhere() -> None:
    result = run("case_change", "en")
    changed = [i for i, (a, b) in enumerate(zip(EN_AUTH, result, strict=True)) if a != b]
    assert len(changed) == 1 and changed[0] != 1
    before, after = EN_AUTH[changed[0]], result[changed[0]]
    assert before != after and before.lower() == after.lower()
    assert sum(x != y for x, y in zip(before, after, strict=True)) == 1


def test_whitespace_noise_doubles_one_space_elsewhere() -> None:
    result = run("whitespace_noise", "en")
    changed = [i for i, (a, b) in enumerate(zip(EN_AUTH, result, strict=True)) if a != b]
    assert len(changed) == 1 and changed[0] != 1
    assert result[changed[0]] == EN_AUTH[changed[0]].replace(" ", "  ", 1)


def test_case_operators_do_not_apply_to_chinese() -> None:
    for name in ("case_change", "same_para_case_change"):
        result = op(name).fn(ZH, ZH_EDIT, "zh", random.Random(0))
        assert isinstance(result, NotApplicable), name
