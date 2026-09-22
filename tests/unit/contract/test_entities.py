import pytest

from artifactdiff.contract.entities import extract_entities
from artifactdiff.contract.models import EvidenceRef


@pytest.fixture
def evidence() -> EvidenceRef:
    return EvidenceRef(block_id="block-1", page_index=0)


def test_extract_entities_normalizes_contract_values(evidence: EvidenceRef) -> None:
    entities = extract_entities(
        "\u7532\u65b9\uff1a\u4e0a\u6d77\u793a\u4f8b\u79d1\u6280\u6709\u9650\u516c\u53f8\uff1b\u4ef7\u6b3e RMB 10,000.00\uff1b45 \u5929\uff1b\u5229\u7387 3.5%\uff1b2026\u5e748\u67084\u65e5",
        "clause-4",
        evidence,
    )

    observed = {(item.kind.value, item.normalized_value) for item in entities}

    assert ("party", "\u4e0a\u6d77\u793a\u4f8b\u79d1\u6280\u6709\u9650\u516c\u53f8") in observed
    assert ("money", "10000.00") in observed
    assert ("currency", "CNY") in observed
    assert ("duration", "45 day") in observed
    assert ("percentage", "3.5") in observed
    assert ("date", "2026-08-04") in observed


def test_extract_entities_has_stable_source_order_and_ids(evidence: EvidenceRef) -> None:
    entities = extract_entities("Party A: Acme Ltd; USD 2,000; 15 days", "clause-1", evidence)

    assert [entity.kind.value for entity in entities] == ["party", "currency", "money", "duration"]
    assert [entity.id for entity in entities] == [
        "entity-02a5f660c1bbb4f0ccb84075",
        "entity-7b48c42120058ae6a2018c9c",
        "entity-9bcadedfebb33f600d41967e",
        "entity-01f827a86553663e7d1c12ea",
    ]
    assert all(entity.evidence == [evidence] for entity in entities)


def test_extract_entities_does_not_match_currency_code_inside_word(evidence: EvidenceRef) -> None:
    entities = extract_entities("CNYx is not a currency amount.", None, evidence)

    assert entities == []


def test_extract_entities_requires_bounded_currency_codes_for_money(
    evidence: EvidenceRef,
) -> None:
    entities = extract_entities("XRMB 100 and 100 CNYx", None, evidence)

    assert entities == []


def test_extract_entities_gives_repeated_money_and_currency_unique_stable_ids(
    evidence: EvidenceRef,
) -> None:
    first = extract_entities("RMB 100 and RMB 100", "clause-1", evidence)
    second = extract_entities("RMB 100 and RMB 100", "clause-1", evidence)

    assert [(item.kind, item.normalized_value) for item in first] == [
        ("currency", "CNY"),
        ("money", "100"),
        ("currency", "CNY"),
        ("money", "100"),
    ]
    assert len({item.id for item in first}) == 4
    assert [item.id for item in second] == [item.id for item in first]


def test_extract_entities_gives_repeated_parties_unique_ids(
    evidence: EvidenceRef,
) -> None:
    entities = extract_entities(
        "Party A: Acme Ltd; Party A: Acme Ltd", "clause-1", evidence
    )

    assert [item.normalized_value for item in entities] == ["Acme Ltd", "Acme Ltd"]
    assert len({item.id for item in entities}) == 2


def test_unrelated_entity_insertion_does_not_renumber_repeated_values(
    evidence: EvidenceRef,
) -> None:
    baseline = extract_entities("RMB 100 and RMB 100", "clause-1", evidence)
    inserted = extract_entities("45 days; RMB 100 and RMB 100", "clause-1", evidence)

    baseline_ids = [
        item.id
        for item in baseline
        if (item.kind.value, item.normalized_value) in {("currency", "CNY"), ("money", "100")}
    ]
    inserted_ids = [
        item.id
        for item in inserted
        if (item.kind.value, item.normalized_value) in {("currency", "CNY"), ("money", "100")}
    ]
    assert inserted_ids == baseline_ids


@pytest.mark.parametrize(
    ("text", "kind", "value"),
    [
        ("甲方应于30天内付款。", "duration", "30 day"),
        ("合同价款为人民币10000元。", "money", "10000"),
        ("合同价款为人民币100万元。", "money", "1000000"),
        ("甲方（接收方）：杭州示例科技有限公司；", "party", "杭州示例科技有限公司"),
        ("违约金为百分之五。", "percentage", "5"),
    ],
)
def test_extract_entities_supports_common_chinese_contract_forms(
    evidence: EvidenceRef, text: str, kind: str, value: str
) -> None:
    observed = {
        (item.kind.value, item.normalized_value)
        for item in extract_entities(text, "clause-zh", evidence)
    }
    assert (kind, value) in observed


def test_chinese_date_components_are_not_duplicated_as_durations(evidence: EvidenceRef) -> None:
    entities = extract_entities("签订日期为2026年9月21日。", "clause-date", evidence)
    assert [(item.kind.value, item.normalized_value) for item in entities] == [
        ("date", "2026-09-21")
    ]
