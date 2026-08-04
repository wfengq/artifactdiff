import hashlib
import json
import unicodedata

import pytest

from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import PolicyValidationError
from artifactdiff.policy import (
    AllowRule,
    ContractPolicy,
    ExactReplace,
    ExpectedRule,
    PolicyBaseline,
    PolicyPluginRequirement,
    canonical_policy_bytes,
    policy_digest,
)


def _selector(heading: str = "Payment") -> ClauseSelector:
    return ClauseSelector(
        clause_label="Section 4",
        heading=heading,
        ancestor_path=("Agreement",),
        anchor="Payment is due within 30 days",
        baseline_fingerprint="baseline-fingerprint",
    )


def _rule(rule_id: str, heading: str = "Payment") -> ExpectedRule:
    return ExpectedRule(
        id=rule_id,
        selector=_selector(heading),
        operation=ExactReplace(before="30 days", after="45 days"),
    )


def _policy(*, heading: str = "Payment", protect: object = None) -> ContractPolicy:
    values: dict[str, object] = {
        "baseline": PolicyBaseline(sha256="a" * 64, format="docx"),
        "expect": [_rule("payment-window", heading)],
        "allow": [AllowRule(selector=_selector(heading), kinds={"moved", "modified"})],
        "required_plugins": {
            "z-plugin": PolicyPluginRequirement(version="1.0", distribution="z-distribution"),
            "a-plugin": PolicyPluginRequirement(version="2.0", distribution="a-distribution"),
        },
    }
    if protect is not None:
        values["protect"] = protect
    return ContractPolicy.model_validate(values)


def test_sets_maps_and_unicode_are_canonicalized() -> None:
    nfc_heading = "Café 付款条件"
    nfd_heading = unicodedata.normalize("NFD", nfc_heading)
    left = _policy(heading=nfc_heading, protect=["money", "dates"])
    right = _policy(heading=nfd_heading, protect=["dates", "money"])

    left_bytes = canonical_policy_bytes(left)

    assert left_bytes == canonical_policy_bytes(right)
    assert "Café 付款条件" in left_bytes.decode("utf-8")
    assert b"\\u" not in left_bytes
    assert json.loads(left_bytes)["protect"] == ["dates", "money"]
    assert list(json.loads(left_bytes)["required_plugins"]) == ["a-plugin", "z-plugin"]


def test_canonical_bytes_preserve_expected_and_allow_rule_order() -> None:
    baseline = PolicyBaseline(sha256="a" * 64, format="pdf")
    first = ContractPolicy(
        baseline=baseline,
        expect=[_rule("first-rule"), _rule("second-rule")],
        allow=[
            AllowRule(selector=_selector("First"), kinds={"modified"}),
            AllowRule(selector=_selector("Second"), kinds={"modified"}),
        ],
    )
    reversed_rules = first.model_copy(
        update={
            "expect": list(reversed(first.expect)),
            "allow": list(reversed(first.allow)),
        }
    )

    first_payload = json.loads(canonical_policy_bytes(first))
    reversed_payload = json.loads(canonical_policy_bytes(reversed_rules))

    assert [item["id"] for item in first_payload["expect"]] == [
        "first-rule",
        "second-rule",
    ]
    assert [item["selector"]["heading"] for item in first_payload["allow"]] == [
        "First",
        "Second",
    ]
    assert canonical_policy_bytes(first) != canonical_policy_bytes(reversed_rules)
    assert [item["id"] for item in reversed_payload["expect"]] == [
        "second-rule",
        "first-rule",
    ]


def test_canonical_bytes_are_compact_utf8_json_and_digest_is_sha256() -> None:
    payload = canonical_policy_bytes(_policy(heading="付款条件"))

    assert payload == json.dumps(
        json.loads(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert policy_digest(_policy(heading="付款条件")) == hashlib.sha256(payload).hexdigest()


def test_canonicalization_rejects_nfc_colliding_mapping_keys() -> None:
    policy = ContractPolicy(
        baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
        required_plugins={
            "é": PolicyPluginRequirement(version="1", distribution="first"),
            "e\u0301": PolicyPluginRequirement(version="1", distribution="second"),
        },
    )

    with pytest.raises(PolicyValidationError):
        canonical_policy_bytes(policy)
