import json
from pathlib import Path

import pytest

from artifactdiff.contract import (
    ClauseLabel,
    ClauseSelector,
    ContractClause,
    ContractDocument,
    LanguageKind,
    LanguageProfile,
)
from artifactdiff.errors import PolicyValidationError
from artifactdiff.models import SourceDescriptor
from artifactdiff.normalize import fingerprint, normalize_text
from artifactdiff.policy import (
    ContractPolicy,
    FrozenPolicy,
    PolicyPluginRequirement,
    draft_exact_replace_policy,
    freeze_policy,
    load_frozen_policy,
    policy_digest,
    write_frozen_policy,
)


def _baseline() -> ContractDocument:
    text = "Section 4 Payment Terms\nPayment is due within 30 days."
    clause = ContractClause(
        id="clause-payment",
        label=ClauseLabel(printed="Section 4", normalized="section 4", scheme="section"),
        heading="Payment Terms",
        ancestor_path=("Agreement",),
        text=text,
        normalized_text=normalize_text(text),
        fingerprint=fingerprint(text),
    )
    return ContractDocument(
        source=SourceDescriptor(
            path="C:/private/customer/baseline.docx",
            sha256="a" * 64,
            format="docx",
            size_bytes=1,
        ),
        language=LanguageProfile(kind=LanguageKind.ENGLISH),
        clauses=[clause],
    )


def _frozen():
    baseline = _baseline()
    selector = ClauseSelector(
        clause_label="section 4",
        heading="Payment Terms",
        ancestor_path=("Agreement",),
        anchor="Payment is due within 30 days.",
    )
    policy = draft_exact_replace_policy(
        baseline,
        selector,
        before="30 days",
        after="45 days",
        rule_id="payment-window",
    )
    return freeze_policy(baseline, policy)


def _redigested_semantically_invalid_frozen(case: str) -> FrozenPolicy:
    policy = _frozen().policy.model_copy(deep=True)
    if case == "empty-expect":
        policy.expect = []
    elif case in {"allow-network", "allow-model"}:
        policy.required_plugins = {
            "CUSTOMER_SECRET": PolicyPluginRequirement(
                version="1",
                distribution="CUSTOMER_SECRET",
                allow_network=case == "allow-network",
                allow_model=case == "allow-model",
            )
        }
    elif case == "missing-fingerprint":
        policy.expect[0].selector.baseline_fingerprint = ""
    elif case == "no-op":
        policy.expect[0].operation.after = policy.expect[0].operation.before
    else:
        policy.expect[0].operation.occurrences = 2
    checked_policy = ContractPolicy.model_validate(policy)
    return FrozenPolicy(
        policy=checked_policy,
        canonical_sha256=policy_digest(checked_policy),
    )


_SEMANTIC_BYPASS_CASES = [
    "empty-expect",
    "allow-network",
    "allow-model",
    "missing-fingerprint",
    "no-op",
    "occurrence-mismatch",
]


def test_frozen_policy_round_trip_is_deterministic_canonical_json(tmp_path: Path) -> None:
    frozen = _frozen()
    first = write_frozen_policy(frozen, tmp_path / "first.json")
    second = write_frozen_policy(frozen, tmp_path / "second.JSON")

    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().endswith(b"}")
    assert b"\n" not in first.read_bytes()
    assert load_frozen_policy(first) == frozen
    assert load_frozen_policy(second) == frozen


def test_load_frozen_policy_rejects_digest_tampering_without_disclosure(
    tmp_path: Path,
) -> None:
    destination = write_frozen_policy(_frozen(), tmp_path / "frozen.json")
    destination.write_text(
        destination.read_text(encoding="utf-8").replace("45 days", "CUSTOMER_SECRET"),
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError, match="digest") as error:
        load_frozen_policy(destination)

    assert "CUSTOMER_SECRET" not in str(error.value)


@pytest.mark.parametrize("case", _SEMANTIC_BYPASS_CASES)
def test_write_rejects_correctly_redigested_semantic_bypasses_before_creating_files(
    tmp_path: Path, case: str
) -> None:
    destination = tmp_path / "CUSTOMER_SECRET.json"

    with pytest.raises(PolicyValidationError) as error:
        write_frozen_policy(_redigested_semantically_invalid_frozen(case), destination)

    assert "CUSTOMER_SECRET" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("case", _SEMANTIC_BYPASS_CASES)
def test_load_rejects_correctly_redigested_semantic_bypasses_nondisclosing(
    tmp_path: Path, case: str
) -> None:
    frozen = _redigested_semantically_invalid_frozen(case)
    destination = tmp_path / "CUSTOMER_SECRET.json"
    destination.write_text(
        json.dumps(
            frozen.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError) as error:
        load_frozen_policy(destination)

    assert "CUSTOMER_SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "contents",
    [
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b'{"required_plugins":{"\xc3\xa9":{},"e\xcc\x81":{}}}',
        b"\xff\xfe\x00",
    ],
)
def test_load_frozen_policy_rejects_duplicate_nfc_and_invalid_utf8(
    tmp_path: Path, contents: bytes
) -> None:
    path = tmp_path / "unsafe.json"
    path.write_bytes(contents)

    with pytest.raises(PolicyValidationError, match="invalid frozen policy file"):
        load_frozen_policy(path)


def test_load_frozen_policy_rejects_oversized_and_deep_files(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * 1_048_576 + b"}")
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 65 + "]" * 65, encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="1 MiB"):
        load_frozen_policy(oversized)
    with pytest.raises(PolicyValidationError, match="invalid frozen policy file"):
        load_frozen_policy(deep)


@pytest.mark.parametrize("operation", ["load", "write"])
def test_frozen_policy_io_rejects_unsupported_suffix_nondisclosing(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "CUSTOMER_SECRET.yaml"
    path.write_text("CUSTOMER_SECRET", encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="unsupported frozen policy format") as error:
        if operation == "load":
            load_frozen_policy(path)
        else:
            write_frozen_policy(_frozen(), path)

    assert "CUSTOMER_SECRET" not in str(error.value)


def test_write_frozen_policy_cleans_temporary_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "frozen.json"

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("CUSTOMER_SECRET destination unavailable")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(PolicyValidationError, match="unable to write frozen policy file") as error:
        write_frozen_policy(_frozen(), destination)

    assert "CUSTOMER_SECRET" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


def test_failed_replace_preserves_existing_frozen_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "frozen.json"
    destination.write_text("existing frozen policy", encoding="utf-8")

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("destination unavailable")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(PolicyValidationError):
        write_frozen_policy(_frozen(), destination)

    assert destination.read_text(encoding="utf-8") == "existing frozen policy"
    assert list(tmp_path.iterdir()) == [destination]


def test_write_frozen_policy_revalidates_before_creating_files(tmp_path: Path) -> None:
    frozen = _frozen()
    frozen.policy.expect[0].operation.before = ""

    with pytest.raises(PolicyValidationError):
        write_frozen_policy(frozen, tmp_path / "frozen.json")

    assert list(tmp_path.iterdir()) == []


def test_write_frozen_policy_rejects_a_stale_digest_before_creating_files(
    tmp_path: Path,
) -> None:
    frozen = _frozen().model_copy(update={"canonical_sha256": "b" * 64})

    with pytest.raises(PolicyValidationError, match="digest"):
        write_frozen_policy(frozen, tmp_path / "frozen.json")

    assert list(tmp_path.iterdir()) == []


def test_load_rejects_valid_shape_with_duplicate_expected_ids(tmp_path: Path) -> None:
    path = write_frozen_policy(_frozen(), tmp_path / "frozen.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["policy"]["expect"].append(payload["policy"]["expect"][0])
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="invalid frozen policy file"):
        load_frozen_policy(path)
