from evaluation.models import (
    VISUAL_UNAVAILABLE_RULE,
    CaseKey,
    CaseResult,
    Expectation,
    text_verdict,
)


def _result(expectation: Expectation, verdict: str | None) -> CaseResult:
    return CaseResult(
        key=CaseKey(source="synthetic", contract_id="c", format="docx", operator="op"),
        expectation=expectation,
        text_verdict=verdict,
        raw_outcome=verdict,
        nonpass_rule_ids=(),
        edited_clause_chars=10,
        baseline_clause_count=2,
        duration_s=0.1,
        error=None if verdict is not None else "boom",
    )


def test_text_verdict_ignores_visual_unavailable() -> None:
    assert text_verdict([("contract-safe.visual.unavailable", "review"), ("x", "pass")]) == "pass"


def test_text_verdict_takes_worst_remaining() -> None:
    assert text_verdict([("a", "review"), ("b", "fail"), ("c", "pass")]) == "fail"
    assert text_verdict([("a", "review"), (VISUAL_UNAVAILABLE_RULE, "review")]) == "review"


def test_false_pass_only_for_block_cases_that_pass() -> None:
    assert _result(Expectation.BLOCK, "pass").false_pass
    assert not _result(Expectation.BLOCK, "review").false_pass
    assert not _result(Expectation.BLOCK, "fail").false_pass
    assert not _result(Expectation.BLOCK, None).false_pass
    assert not _result(Expectation.ACCEPT, "pass").false_pass
    assert _result(Expectation.ACCEPT, "pass").accepted
    assert not _result(Expectation.ACCEPT, "review").accepted
    assert not _result(Expectation.ACCEPT, None).accepted
    assert not _result(Expectation.BLOCK, "pass").accepted


def test_case_result_to_json_round_trips_key_fields() -> None:
    payload = _result(Expectation.BLOCK, "fail").to_json()
    assert payload["key"] == {
        "source": "synthetic",
        "contract_id": "c",
        "format": "docx",
        "operator": "op",
    }
    assert set(payload) == {
        "key",
        "expectation",
        "text_verdict",
        "raw_outcome",
        "nonpass_rule_ids",
        "edited_clause_chars",
        "baseline_clause_count",
        "duration_s",
        "error",
    }
    assert payload["expectation"] == "block"
    assert payload["nonpass_rule_ids"] == []


def test_case_keys_sort_by_source_contract_format_operator() -> None:
    keys = [
        CaseKey("synthetic", "b", "docx", "a"),
        CaseKey("cuad", "z", "pdf", "z"),
        CaseKey("synthetic", "a", "pdf", "a"),
        CaseKey("synthetic", "a", "docx", "b"),
    ]
    assert sorted(keys) == [keys[1], keys[3], keys[2], keys[0]]
