import json
from pathlib import Path

import pytest

from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import PolicyValidationError
from artifactdiff.policy import (
    ContractPolicy,
    ExactReplace,
    ExpectedRule,
    PolicyBaseline,
    canonical_policy_bytes,
    load_policy,
    write_policy,
)

MAX_POLICY_BYTES = 1_048_576


def _policy() -> ContractPolicy:
    selector = ClauseSelector(
        clause_label="第四条",
        heading="Café 付款条件",
        ancestor_path=("主协议",),
        anchor="发票开具后 30 天内付款",
        baseline_fingerprint="baseline-fingerprint",
    )
    return ContractPolicy(
        baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
        expect=[
            ExpectedRule(
                id="payment-window",
                selector=selector,
                operation=ExactReplace(before="30 天", after="45 天"),
            )
        ],
        protect={"money", "dates"},
    )


def test_yaml_json_and_python_produce_identical_canonical_bytes(
    tmp_path: Path,
) -> None:
    yaml_path = tmp_path / "policy.yaml"
    yaml_path.write_text(
        """\
protect:
  - dates
  - money
expect:
  - operation:
      after: 45 天
      before: 30 天
      type: exact_replace
    selector:
      anchor: 发票开具后 30 天内付款
      ancestor_path: [主协议]
      baseline_fingerprint: baseline-fingerprint
      clause_label: 第四条
      heading: Café 付款条件
    id: payment-window
baseline:
  format: docx
  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
        encoding="utf-8",
    )
    json_path = tmp_path / "policy.json"
    json_path.write_text(
        json.dumps(
            {
                "protect": ["money", "dates"],
                "baseline": {"format": "docx", "sha256": "a" * 64},
                "expect": [
                    {
                        "selector": {
                            "heading": "Café 付款条件",
                            "clause_label": "第四条",
                            "anchor": "发票开具后 30 天内付款",
                            "ancestor_path": ["主协议"],
                            "baseline_fingerprint": "baseline-fingerprint",
                        },
                        "operation": {
                            "before": "30 天",
                            "after": "45 天",
                            "type": "exact_replace",
                        },
                        "id": "payment-window",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    python_bytes = canonical_policy_bytes(_policy())

    assert canonical_policy_bytes(load_policy(yaml_path)) == python_bytes
    assert canonical_policy_bytes(load_policy(json_path)) == python_bytes


@pytest.mark.parametrize("suffix", [".json", ".yaml", ".yml"])
def test_write_policy_round_trips_deterministically(tmp_path: Path, suffix: str) -> None:
    first = tmp_path / f"first{suffix}"
    second = tmp_path / f"second{suffix}"

    assert write_policy(_policy(), first) == first
    write_policy(_policy(), second)

    assert first.read_bytes() == second.read_bytes()
    assert load_policy(first) == _policy()
    assert canonical_policy_bytes(load_policy(first)) == canonical_policy_bytes(_policy())
    if suffix == ".json":
        assert first.read_bytes() == canonical_policy_bytes(_policy())
    else:
        assert b"!!python" not in first.read_bytes()


@pytest.mark.parametrize(
    ("name", "contents"),
    [
        (
            "alias.yaml",
            "baseline: &base {sha256: " + "a" * 64 + ", format: docx}\ncopy: *base\n",
        ),
        (
            "custom-tag.yaml",
            "baseline: !!python/object/apply:os.system ['TOP_SECRET']\n",
        ),
        (
            "multiple.yaml",
            "baseline: {sha256: " + "a" * 64 + ", format: docx}\n---\nTOP_SECRET\n",
        ),
        (
            "duplicate.yaml",
            "baseline: {sha256: "
            + "a" * 64
            + ", format: docx}\nbaseline: {sha256: "
            + "b" * 64
            + ", format: pdf}\n",
        ),
        (
            "merge.yaml",
            "baseline:\n  <<: {sha256: " + "a" * 64 + ", format: docx}\n",
        ),
        ("non-string-key.yaml", "1: TOP_SECRET\n"),
        ("non-object.yaml", "[TOP_SECRET]\n"),
        (
            "unknown-field.yaml",
            "baseline: {sha256: " + "a" * 64 + ", format: docx}\ncallback: TOP_SECRET\n",
        ),
        (
            "duplicate.json",
            '{"baseline":{"sha256":"' + "a" * 64 + '","format":"docx"},"baseline":"TOP_SECRET"}',
        ),
        ("non-object.json", '["TOP_SECRET"]'),
    ],
)
def test_load_policy_rejects_unsafe_input_without_disclosing_contents(
    tmp_path: Path, name: str, contents: str
) -> None:
    path = tmp_path / name
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(PolicyValidationError) as error:
        load_policy(path)

    assert "TOP_SECRET" not in str(error.value)


@pytest.mark.parametrize("suffix", [".yaml", ".json"])
def test_load_policy_rejects_nfc_colliding_mapping_keys(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"collision{suffix}"
    if suffix == ".json":
        contents = (
            '{"baseline":{"sha256":"'
            + "a" * 64
            + '","format":"docx"},"required_plugins":'
            + '{"é":{"version":"1","distribution":"first"},'
            + '"e\\u0301":{"version":"1","distribution":"second"}}}'
        )
    else:
        contents = (
            "baseline: {sha256: "
            + "a" * 64
            + ", format: docx}\nrequired_plugins:\n"
            + "  é: {version: '1', distribution: first}\n"
            + "  e\u0301: {version: '1', distribution: second}\n"
        )
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(PolicyValidationError):
        load_policy(path)


def test_load_policy_rejects_invalid_utf8_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(b'{"secret":"TOP_SECRET\xff"}')

    with pytest.raises(PolicyValidationError) as error:
        load_policy(path)

    assert "TOP_SECRET" not in str(error.value)


def test_load_policy_rejects_oversized_files_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_bytes(b"x" * (MAX_POLICY_BYTES + 1))

    with pytest.raises(PolicyValidationError):
        load_policy(path)


@pytest.mark.parametrize("operation", ["load", "write"])
def test_policy_io_rejects_unknown_suffixes(tmp_path: Path, operation: str) -> None:
    path = tmp_path / "policy.txt"
    path.write_text("TOP_SECRET", encoding="utf-8")

    with pytest.raises(PolicyValidationError) as error:
        if operation == "load":
            load_policy(path)
        else:
            write_policy(_policy(), path)

    assert "TOP_SECRET" not in str(error.value)


def test_write_policy_removes_temporary_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "policy.json"

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("destination unavailable")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="destination unavailable"):
        write_policy(_policy(), destination)

    assert list(tmp_path.iterdir()) == []


def test_failed_replace_preserves_existing_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "policy.yaml"
    destination.write_text("existing policy", encoding="utf-8")

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("destination unavailable")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="destination unavailable"):
        write_policy(_policy(), destination)

    assert destination.read_text(encoding="utf-8") == "existing policy"
    assert list(tmp_path.iterdir()) == [destination]
