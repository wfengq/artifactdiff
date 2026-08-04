"""Baseline-bound policy drafting, validation, freezing, and frozen JSON IO."""

import json
import tempfile
import unicodedata
from pathlib import Path

from pydantic import ValidationError
from pydantic_core import PydanticSerializationError

from artifactdiff.contract import (
    ClauseSelector,
    ContractClause,
    ContractDocument,
    SelectorResolutionStatus,
    resolve_baseline,
)
from artifactdiff.errors import PolicyValidationError
from artifactdiff.policy.canonical import _normalize, canonical_policy_bytes, policy_digest
from artifactdiff.policy.io import MAX_POLICY_BYTES, _load_json
from artifactdiff.policy.models import (
    ContractPolicy,
    ExactReplace,
    ExpectedRule,
    FrozenPolicy,
    PolicyBaseline,
)
from artifactdiff.policy.profile import validate_contract_safe_plugins

SUPPORTED_FROZEN_POLICY_SUFFIXES = frozenset({".json"})


def _invalid_contract_policy() -> PolicyValidationError:
    return PolicyValidationError("invalid contract policy")


def _validated_baseline(baseline: ContractDocument) -> ContractDocument:
    try:
        payload = baseline.model_dump(mode="python", warnings="error")
        return ContractDocument.model_validate(payload)
    except (
        ValidationError,
        PydanticSerializationError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        raise PolicyValidationError("invalid inspected contract") from None


def _validated_policy(policy: ContractPolicy) -> ContractPolicy:
    try:
        return ContractPolicy.model_validate(policy)
    except (ValidationError, RecursionError, OverflowError, TypeError, ValueError):
        raise _invalid_contract_policy() from None


def _canonicalized_policy(policy: ContractPolicy) -> ContractPolicy:
    validated = _validated_policy(policy)
    try:
        return ContractPolicy.model_validate(json.loads(canonical_policy_bytes(validated)))
    except (ValidationError, json.JSONDecodeError, RecursionError, OverflowError):
        raise _invalid_contract_policy() from None


def _validate_expected_rule_semantics(rule: ExpectedRule) -> None:
    if not rule.selector.baseline_fingerprint:
        raise PolicyValidationError("expected selector fingerprint is required")
    if _nfc(rule.operation.before) == _nfc(rule.operation.after):
        raise PolicyValidationError("expected replacement must change text")
    if rule.operation.occurrences != rule.selector.occurrences:
        raise PolicyValidationError("expected replacement occurrence mismatch")


def _validate_contract_safe_semantics(policy: ContractPolicy) -> None:
    if not policy.expect:
        raise PolicyValidationError("contract-safe requires at least one exact expected operation")
    validate_contract_safe_plugins(policy)
    for expected_rule in policy.expect:
        _validate_expected_rule_semantics(expected_rule)


def _validated_contract_safe_policy(policy: ContractPolicy) -> ContractPolicy:
    canonical_policy = _canonicalized_policy(policy)
    _validate_contract_safe_semantics(canonical_policy)
    return canonical_policy


def _validated_selector(selector: ClauseSelector) -> ClauseSelector:
    try:
        return ClauseSelector.model_validate(selector)
    except (ValidationError, RecursionError, OverflowError, TypeError, ValueError):
        raise PolicyValidationError("invalid contract selector") from None


def _resolve_unique_clause(baseline: ContractDocument, selector: ClauseSelector) -> ContractClause:
    resolution = resolve_baseline(baseline, selector)
    if resolution.status is not SelectorResolutionStatus.UNIQUE or len(resolution.matches) != 1:
        raise PolicyValidationError("policy selector must resolve exactly once")
    clause_id = resolution.matches[0].clause_id
    matching_clauses = [clause for clause in baseline.clauses if clause.id == clause_id]
    if len(matching_clauses) != 1:
        raise PolicyValidationError("policy selector must resolve exactly once")
    return matching_clauses[0]


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _validate_exact_operation(clause: ContractClause, rule: ExpectedRule) -> None:
    operation = rule.operation
    clause_text = _nfc(clause.text)
    before = _nfc(operation.before)
    after = _nfc(operation.after)
    if clause_text.count(before) != operation.occurrences:
        raise PolicyValidationError("expected text occurrence mismatch")
    expected_clause = clause_text.replace(before, after, operation.occurrences)
    if expected_clause.count(after) != operation.occurrences:
        raise PolicyValidationError("expected replacement occurrence ambiguity")


def draft_exact_replace_policy(
    baseline: ContractDocument,
    selector: ClauseSelector,
    *,
    before: str,
    after: str,
    rule_id: str,
) -> ContractPolicy:
    """Draft one exact replacement bound only to a baseline hash and format."""
    checked_baseline = _validated_baseline(baseline)
    supplied_selector = _validated_selector(selector)
    clause = _resolve_unique_clause(checked_baseline, supplied_selector)
    try:
        exact_selector = ClauseSelector(
            clause_label=clause.label.normalized,
            heading=clause.heading,
            ancestor_path=clause.ancestor_path,
            anchor=supplied_selector.anchor,
            baseline_fingerprint=clause.fingerprint,
            occurrences=supplied_selector.occurrences,
            matcher_version=supplied_selector.matcher_version,
            min_similarity=supplied_selector.min_similarity,
            min_margin=supplied_selector.min_margin,
        )
        rule = ExpectedRule(
            id=rule_id,
            selector=exact_selector,
            operation=ExactReplace(
                before=before,
                after=after,
                occurrences=supplied_selector.occurrences,
            ),
        )
        _validate_expected_rule_semantics(rule)
        _validate_exact_operation(clause, rule)
        return ContractPolicy(
            baseline=PolicyBaseline(
                sha256=checked_baseline.source.sha256,
                format=checked_baseline.source.format,
            ),
            expect=[rule],
        )
    except PolicyValidationError:
        raise
    except (ValidationError, RecursionError, OverflowError, TypeError, ValueError):
        raise _invalid_contract_policy() from None


def validate_policy(baseline: ContractDocument, policy: ContractPolicy) -> None:
    """Fail closed unless a contract-safe policy is exact for this baseline."""
    checked_baseline = _validated_baseline(baseline)
    checked_policy = _validated_policy(policy)
    if (
        checked_policy.baseline.sha256 != checked_baseline.source.sha256
        or checked_policy.baseline.format != checked_baseline.source.format
    ):
        raise PolicyValidationError("policy baseline does not match the inspected contract")
    resolved_expected: list[tuple[ExpectedRule, ContractClause]] = []
    for expected_rule in checked_policy.expect:
        clause = _resolve_unique_clause(checked_baseline, expected_rule.selector)
        if expected_rule.selector.baseline_fingerprint != clause.fingerprint:
            raise PolicyValidationError("expected selector fingerprint mismatch")
        resolved_expected.append((expected_rule, clause))
    for allow_rule in checked_policy.allow:
        _resolve_unique_clause(checked_baseline, allow_rule.selector)
    _validate_contract_safe_semantics(checked_policy)
    for expected_rule, clause in resolved_expected:
        _validate_exact_operation(clause, expected_rule)


def freeze_policy(baseline: ContractDocument, policy: ContractPolicy) -> FrozenPolicy:
    """Validate and snapshot a deterministic locally assured policy."""
    checked_policy = _validated_contract_safe_policy(policy)
    validate_policy(baseline, checked_policy)
    try:
        return FrozenPolicy(
            policy=checked_policy,
            canonical_sha256=policy_digest(checked_policy),
            assurance="local",
        )
    except (ValidationError, RecursionError, OverflowError, TypeError, ValueError):
        raise PolicyValidationError("invalid frozen policy") from None


def _validated_frozen_policy(policy: FrozenPolicy) -> FrozenPolicy:
    try:
        validated = FrozenPolicy.model_validate(policy)
        canonical_policy = _validated_contract_safe_policy(validated.policy)
        canonical_digest = policy_digest(canonical_policy)
        if validated.canonical_sha256 != canonical_digest:
            raise PolicyValidationError("frozen policy digest mismatch")
        return FrozenPolicy(
            schema_version=validated.schema_version,
            policy=canonical_policy,
            canonical_sha256=canonical_digest,
            assurance=validated.assurance,
        )
    except PolicyValidationError:
        raise
    except (ValidationError, RecursionError, OverflowError, TypeError, ValueError):
        raise PolicyValidationError("invalid frozen policy") from None


def _frozen_policy_bytes(policy: FrozenPolicy) -> bytes:
    validated = _validated_frozen_policy(policy)
    normalized = _normalize(validated.model_dump(mode="python"))
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_frozen_policy(policy: FrozenPolicy, path: Path) -> Path:
    """Atomically write one bounded deterministic frozen-policy JSON artifact."""
    if path.suffix.casefold() not in SUPPORTED_FROZEN_POLICY_SUFFIXES:
        raise PolicyValidationError("unsupported frozen policy format")
    contents = _frozen_policy_bytes(policy)
    if len(contents) > MAX_POLICY_BYTES:
        raise PolicyValidationError("frozen policy file exceeds 1 MiB limit")

    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(contents)
            stream.flush()
        temporary.replace(path)
    except OSError:
        raise PolicyValidationError("unable to write frozen policy file") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return path


def load_frozen_policy(path: Path) -> FrozenPolicy:
    """Load bounded canonical JSON and verify its embedded policy digest."""
    if path.suffix.casefold() not in SUPPORTED_FROZEN_POLICY_SUFFIXES:
        raise PolicyValidationError("unsupported frozen policy format")
    try:
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyValidationError("frozen policy file exceeds 1 MiB limit")
        raw = path.read_bytes()
    except PolicyValidationError:
        raise
    except OSError:
        raise PolicyValidationError("unable to read frozen policy file") from None
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyValidationError("frozen policy file exceeds 1 MiB limit")
    try:
        payload = _load_json(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        frozen = FrozenPolicy.model_validate(payload)
    except (
        UnicodeDecodeError,
        ValidationError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        raise PolicyValidationError("invalid frozen policy file") from None
    return _validated_frozen_policy(frozen)
