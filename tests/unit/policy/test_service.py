import json

import pytest

import artifactdiff
import artifactdiff.policy as policy_api
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
    AllowRule,
    ContractPolicy,
    ExactReplace,
    ExpectedRule,
    PolicyBaseline,
    PolicyPluginRequirement,
    draft_exact_replace_policy,
    freeze_policy,
    policy_digest,
    validate_policy,
)


def _clause(
    clause_id: str = "clause-payment",
    *,
    label: str = "Section 4",
    normalized_label: str | None = None,
    heading: str = "Payment Terms",
    ancestor_path: tuple[str, ...] = ("Agreement",),
    text: str = "Section 4 Payment Terms\nPayment is due within 30 days.",
) -> ContractClause:
    return ContractClause(
        id=clause_id,
        label=ClauseLabel(
            printed=label,
            normalized=normalized_label or normalize_text(label),
            scheme="section",
        ),
        heading=heading,
        ancestor_path=ancestor_path,
        text=text,
        normalized_text=normalize_text(text),
        fingerprint=fingerprint(text),
    )


def _contract(
    *clauses: ContractClause,
    sha256: str = "a" * 64,
    format_name: str = "docx",
) -> ContractDocument:
    return ContractDocument(
        source=SourceDescriptor(
            path="C:/private/customer/baseline.docx",
            sha256=sha256,
            format=format_name,
            size_bytes=937_421,
        ),
        language=LanguageProfile(kind=LanguageKind.BILINGUAL),
        clauses=list(clauses) or [_clause()],
    )


def _selector(clause: ContractClause | None = None, **updates: object) -> ClauseSelector:
    selected = clause or _clause()
    payload: dict[str, object] = {
        "clause_label": selected.label.normalized,
        "heading": selected.heading,
        "ancestor_path": selected.ancestor_path,
        "anchor": "Payment is due within 30 days.",
        "baseline_fingerprint": selected.fingerprint,
        "occurrences": 1,
    }
    payload.update(updates)
    return ClauseSelector.model_validate(payload)


def _policy(
    contract: ContractDocument | None = None,
    *,
    selector: ClauseSelector | None = None,
    before: str = "30 days",
    after: str = "45 days",
    operation_occurrences: int = 1,
    allow: list[AllowRule] | None = None,
    required_plugins: dict[str, PolicyPluginRequirement] | None = None,
) -> ContractPolicy:
    baseline = contract or _contract()
    selected = selector or _selector(baseline.clauses[0])
    return ContractPolicy(
        baseline=PolicyBaseline(
            sha256=baseline.source.sha256,
            format=baseline.source.format,
        ),
        expect=[
            ExpectedRule(
                id="payment-window",
                selector=selected,
                operation=ExactReplace(
                    before=before,
                    after=after,
                    occurrences=operation_occurrences,
                ),
            )
        ],
        allow=allow or [],
        required_plugins=required_plugins or {},
    )


def test_policy_service_interfaces_are_public() -> None:
    assert policy_api.draft_exact_replace_policy is draft_exact_replace_policy
    assert policy_api.freeze_policy is freeze_policy
    assert policy_api.validate_policy is validate_policy
    assert artifactdiff.draft_exact_replace_policy is draft_exact_replace_policy
    assert artifactdiff.freeze_policy is freeze_policy


@pytest.mark.parametrize(
    ("label", "normalized_label", "heading", "ancestor_path", "anchor"),
    [
        ("第四条", "第四条", "付款条件", ("主协议",), "发票后 30 天内付款"),
        (
            "Section 4",
            "section 4",
            "Payment Terms",
            ("Agreement",),
            "Payment is due within 30 days",
        ),
        (
            "第四条 / Section 4",
            "第四条 section 4",
            "付款条件 / Payment Terms",
            ("主协议 / Agreement",),
            "应在 30 days 内付款 / Payment is due",
        ),
    ],
)
def test_draft_copies_exact_baseline_identity_and_caller_occurrence_intent(
    label: str,
    normalized_label: str,
    heading: str,
    ancestor_path: tuple[str, ...],
    anchor: str,
) -> None:
    text = f"{label} {heading}\n{anchor}"
    clause = _clause(
        label=label,
        normalized_label=normalized_label,
        heading=heading,
        ancestor_path=ancestor_path,
        text=text,
    )
    baseline = _contract(clause)
    supplied = ClauseSelector(
        clause_label=normalized_label.upper(),
        heading=heading.swapcase(),
        ancestor_path=tuple(item.swapcase() for item in ancestor_path),
        anchor=anchor,
        occurrences=1,
        min_similarity=0.97,
        min_margin=0.08,
    )

    policy = draft_exact_replace_policy(
        baseline,
        supplied,
        before="30 days" if "30 days" in text else "30 天",
        after="45 days" if "30 days" in text else "45 天",
        rule_id="payment-window",
    )

    drafted = policy.expect[0]
    assert drafted.selector.clause_label == clause.label.normalized
    assert drafted.selector.heading == clause.heading
    assert drafted.selector.ancestor_path == clause.ancestor_path
    assert drafted.selector.anchor == anchor
    assert drafted.selector.occurrences == supplied.occurrences
    assert drafted.selector.baseline_fingerprint == clause.fingerprint
    assert drafted.selector.min_similarity == 0.97
    assert drafted.selector.min_margin == 0.08
    assert drafted.operation.occurrences == supplied.occurrences


def test_draft_binds_only_source_hash_and_format() -> None:
    baseline = _contract()

    policy = draft_exact_replace_policy(
        baseline,
        _selector(baseline.clauses[0]),
        before="30 days",
        after="45 days",
        rule_id="payment-window",
    )

    payload = policy.model_dump(mode="json")["baseline"]
    assert payload == {"sha256": "a" * 64, "format": "docx"}
    serialized = json.dumps(policy.model_dump(mode="json"))
    assert "private/customer" not in serialized
    assert "937421" not in serialized


def test_draft_rejects_ambiguous_selector_without_disclosing_clause_data() -> None:
    secret = "CUSTOMER_SECRET Payment is due within 30 days."
    first = _clause("clause-a", text=secret)
    second = first.model_copy(update={"id": "clause-b"})
    selector = _selector(first, baseline_fingerprint="")

    with pytest.raises(PolicyValidationError, match="must resolve exactly once") as error:
        draft_exact_replace_policy(
            _contract(first, second),
            selector,
            before="30 days",
            after="45 days",
            rule_id="payment-window",
        )

    assert "CUSTOMER_SECRET" not in str(error.value)


@pytest.mark.parametrize(
    ("before", "after", "occurrences"),
    [
        ("missing", "45 days", 1),
        ("30 days", "45 days", 2),
        ("30 days", "30 days", 1),
        ("30 days", "already present", 1),
    ],
)
def test_draft_rejects_count_mismatch_noop_and_existing_after_text(
    before: str, after: str, occurrences: int
) -> None:
    clause = _clause(text="Payment is due within 30 days; already present remains.")
    selector = _selector(clause, anchor="Payment is due within 30 days", occurrences=occurrences)

    with pytest.raises(PolicyValidationError):
        draft_exact_replace_policy(
            _contract(clause),
            selector,
            before=before,
            after=after,
            rule_id="payment-window",
        )


@pytest.mark.parametrize(
    "policy_update",
    [
        {"baseline": PolicyBaseline(sha256="b" * 64, format="docx")},
        {"baseline": PolicyBaseline(sha256="a" * 64, format="pdf")},
        {"expect": []},
    ],
)
def test_validate_rejects_baseline_mismatch_and_empty_expect(
    policy_update: dict[str, object],
) -> None:
    baseline = _contract()
    policy = _policy(baseline).model_copy(update=policy_update)

    with pytest.raises(PolicyValidationError):
        validate_policy(baseline, policy)


def test_validate_rejects_mutated_duplicate_expected_ids() -> None:
    baseline = _contract()
    policy = _policy(baseline)
    duplicate = policy.expect[0].model_copy(update={"id": "other-window"})
    policy.expect.append(duplicate)
    policy.expect[1].id = "payment-window"

    with pytest.raises(PolicyValidationError):
        validate_policy(baseline, policy)


@pytest.mark.parametrize("capability", ["allow_network", "allow_model"])
def test_validate_rejects_unsafe_plugin_capabilities(capability: str) -> None:
    baseline = _contract()
    plugin = PolicyPluginRequirement(
        version="1.2.3",
        distribution="artifactdiff-safe-plugin",
        **{capability: True},
    )

    with pytest.raises(PolicyValidationError, match="plugin capabilities"):
        validate_policy(baseline, _policy(baseline, required_plugins={"safe-plugin": plugin}))


def test_validate_accepts_declarative_local_plugin_requirement() -> None:
    baseline = _contract()
    plugin = PolicyPluginRequirement(
        version="1.2.3",
        distribution="artifactdiff-safe-plugin",
    )

    validate_policy(baseline, _policy(baseline, required_plugins={"safe-plugin": plugin}))


def test_validate_rejects_ambiguous_allow_rule() -> None:
    first = _clause("clause-a")
    second = first.model_copy(update={"id": "clause-b"})
    baseline = _contract(first, second)
    expected_selector = _selector(first)
    allow_selector = _selector(first, baseline_fingerprint="")
    allow = AllowRule(selector=allow_selector, kinds=frozenset({"modified"}))

    with pytest.raises(PolicyValidationError, match="must resolve exactly once"):
        validate_policy(baseline, _policy(baseline, selector=expected_selector, allow=[allow]))


def test_validate_requires_expected_selector_fingerprint_binding() -> None:
    baseline = _contract()
    selector = _selector(baseline.clauses[0], baseline_fingerprint="")

    with pytest.raises(PolicyValidationError, match="fingerprint"):
        validate_policy(baseline, _policy(baseline, selector=selector))


@pytest.mark.parametrize(
    ("mutation", "expected_message"),
    [
        ("operation-count", "occurrence"),
        ("before-count", "occurrence"),
        ("after-count", "replacement"),
        ("no-op", "replacement"),
        ("fingerprint", "must resolve exactly once"),
        ("anchor-count", "must resolve exactly once"),
    ],
)
def test_validate_rejects_inconsistent_exact_operation_state(
    mutation: str, expected_message: str
) -> None:
    baseline = _contract()
    policy = _policy(baseline)
    if mutation == "operation-count":
        policy.expect[0].operation.occurrences = 2
    elif mutation == "before-count":
        policy.expect[0].operation.before = "missing"
    elif mutation == "after-count":
        policy.expect[0].operation.after = "Payment"
    elif mutation == "no-op":
        policy.expect[0].operation.after = "30 days"
    elif mutation == "fingerprint":
        policy.expect[0].selector.baseline_fingerprint = "wrong"
    else:
        policy.expect[0].selector.occurrences = 2

    with pytest.raises(PolicyValidationError, match=expected_message):
        validate_policy(baseline, policy)


def test_validate_revalidates_invalid_nested_policy_models() -> None:
    baseline = _contract()
    policy = _policy(baseline)
    policy.expect[0].operation.before = ""

    with pytest.raises(PolicyValidationError, match="invalid contract policy"):
        validate_policy(baseline, policy)


def test_freeze_is_deterministic_and_snapshots_revalidated_policy() -> None:
    baseline = _contract()
    policy = _policy(baseline)

    first = freeze_policy(baseline, policy)
    second = freeze_policy(baseline, policy)
    policy.expect[0].operation.after = "60 days"

    assert first == second
    assert first.assurance == "local"
    assert first.canonical_sha256 == policy_digest(first.policy)
    assert first.policy.expect[0].operation.after == "45 days"


def test_freeze_rejects_mutated_baseline_and_invalid_policy() -> None:
    baseline = _contract()
    policy = _policy(baseline)
    baseline.source.sha256 = "b" * 64

    with pytest.raises(PolicyValidationError):
        freeze_policy(baseline, policy)

    baseline.source.sha256 = "a" * 64
    policy.expect[0].selector.ancestor_path = {"Agreement", "Schedule"}
    with pytest.raises(PolicyValidationError):
        freeze_policy(baseline, policy)
