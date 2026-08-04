from collections.abc import Callable

import pytest
from pydantic import ValidationError

import artifactdiff
import artifactdiff.policy as policy_api
from artifactdiff.contract import ClauseSelector
from artifactdiff.models import StrictModel
from artifactdiff.policy import (
    AllowRule,
    ContractPolicy,
    EvidenceMode,
    EvidencePolicy,
    ExactReplace,
    ExpectedRule,
    FrozenPolicy,
    MetadataPolicy,
    PolicyBaseline,
    PolicyPluginRequirement,
    ProtectedTarget,
    VisualPolicy,
)


def _selector() -> ClauseSelector:
    return ClauseSelector(
        clause_label="Section 4",
        heading="Payment",
        ancestor_path=("Agreement",),
        anchor="Payment is due within 30 days",
        baseline_fingerprint="baseline-fingerprint",
    )


def _expected_rule(rule_id: str = "payment-window") -> ExpectedRule:
    return ExpectedRule(
        id=rule_id,
        selector=_selector(),
        operation=ExactReplace(before="30 days", after="45 days"),
    )


def test_policy_defaults_to_contract_safe_minimal_and_all_protected() -> None:
    policy = ContractPolicy(baseline=PolicyBaseline(sha256="a" * 64, format="docx"))

    assert policy.profile == "contract-safe"
    assert policy.profile_version == "1.0"
    assert policy.visual.on_unavailable == "review"
    assert policy.evidence.mode is EvidenceMode.MINIMAL
    assert policy.protect == frozenset(ProtectedTarget)


def test_policy_models_are_strict_public_interfaces() -> None:
    public_models = (
        ExactReplace,
        ExpectedRule,
        AllowRule,
        VisualPolicy,
        MetadataPolicy,
        PolicyPluginRequirement,
        PolicyBaseline,
        ContractPolicy,
        FrozenPolicy,
    )

    assert all(issubclass(model, StrictModel) for model in public_models)
    assert policy_api.ContractPolicy is ContractPolicy
    assert artifactdiff.ContractPolicy is ContractPolicy


def test_policy_rejects_executable_or_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ContractPolicy.model_validate(
            {
                "baseline": {"sha256": "a" * 64, "format": "docx"},
                "callback": "os.system('x')",
            }
        )


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: ExactReplace(before="", after="replacement"),
            id="empty-before",
        ),
        pytest.param(
            lambda: ExactReplace(before="original", after="x" * 10_001),
            id="oversized-after",
        ),
        pytest.param(
            lambda: ExactReplace(before="original", after="replacement", occurrences=0),
            id="zero-occurrences",
        ),
        pytest.param(
            lambda: ExactReplace(before="original", after="replacement", occurrences=True),
            id="boolean-occurrences",
        ),
        pytest.param(
            lambda: ExpectedRule(
                id="Invalid_ID", selector=_selector(), operation=_expected_rule().operation
            ),
            id="invalid-rule-id",
        ),
        pytest.param(
            lambda: AllowRule(selector=_selector(), kinds=frozenset()),
            id="empty-allow-kinds",
        ),
        pytest.param(
            lambda: PolicyBaseline(sha256="A" * 64, format="docx"),
            id="uppercase-baseline-hash",
        ),
        pytest.param(
            lambda: VisualPolicy(layout_envelope_padding_points=True),
            id="boolean-padding",
        ),
        pytest.param(
            lambda: PolicyPluginRequirement(version="", distribution="plugin"),
            id="empty-plugin-version",
        ),
        pytest.param(
            lambda: PolicyPluginRequirement(
                version="1", distribution="plugin", allow_network="false"
            ),
            id="coerced-plugin-boolean",
        ),
    ],
)
def test_policy_models_reject_invalid_or_ambiguous_values(
    build: Callable[[], object],
) -> None:
    with pytest.raises(ValidationError):
        build()


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: ExactReplace(type=b"exact_replace", before="old", after="new"),
            id="operation-type",
        ),
        pytest.param(
            lambda: ExactReplace(before=b"old", after="new"),
            id="operation-before",
        ),
        pytest.param(
            lambda: ExactReplace(before="old", after=b"new"),
            id="operation-after",
        ),
        pytest.param(
            lambda: ExpectedRule(
                id=b"payment-window",
                selector=_selector(),
                operation=ExactReplace(before="old", after="new"),
            ),
            id="expected-id",
        ),
        pytest.param(
            lambda: AllowRule(selector=_selector(), kinds=[b"modified"]),
            id="allow-kind",
        ),
        pytest.param(
            lambda: VisualPolicy(explained_regions=b"pass"),
            id="visual-explained",
        ),
        pytest.param(
            lambda: VisualPolicy(pagination_reflow=b"review"),
            id="visual-pagination",
        ),
        pytest.param(
            lambda: VisualPolicy(protected_region_change=b"fail"),
            id="visual-protected",
        ),
        pytest.param(
            lambda: VisualPolicy(on_unavailable=b"review"),
            id="visual-unavailable",
        ),
        pytest.param(
            lambda: EvidencePolicy(mode=b"minimal"),
            id="evidence-mode",
        ),
        pytest.param(
            lambda: MetadataPolicy(non_business_change=b"review"),
            id="metadata-mode",
        ),
        pytest.param(
            lambda: PolicyBaseline(sha256=b"a" * 64, format="docx"),
            id="baseline-sha",
        ),
        pytest.param(
            lambda: PolicyBaseline(sha256="a" * 64, format=b"docx"),
            id="baseline-format",
        ),
        pytest.param(
            lambda: PolicyPluginRequirement(version=b"1", distribution="plugin"),
            id="plugin-version",
        ),
        pytest.param(
            lambda: PolicyPluginRequirement(version="1", distribution=b"plugin"),
            id="plugin-distribution",
        ),
        pytest.param(
            lambda: ContractPolicy(
                schema_version=b"1.0",
                baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
            ),
            id="policy-schema",
        ),
        pytest.param(
            lambda: ContractPolicy(
                profile=b"contract-safe",
                baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
            ),
            id="policy-profile",
        ),
        pytest.param(
            lambda: ContractPolicy(
                profile_version=b"1.0",
                baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
            ),
            id="policy-profile-version",
        ),
        pytest.param(
            lambda: ContractPolicy(
                baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
                protect=[b"money"],
            ),
            id="protected-target",
        ),
        pytest.param(
            lambda: ContractPolicy(
                baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
                required_plugins={
                    b"plugin": PolicyPluginRequirement(version="1", distribution="plugin")
                },
            ),
            id="plugin-name",
        ),
        pytest.param(
            lambda: FrozenPolicy(
                schema_version=b"1.0",
                policy=ContractPolicy(baseline=PolicyBaseline(sha256="a" * 64, format="docx")),
                canonical_sha256="b" * 64,
            ),
            id="frozen-schema",
        ),
        pytest.param(
            lambda: FrozenPolicy(
                policy=ContractPolicy(baseline=PolicyBaseline(sha256="a" * 64, format="docx")),
                canonical_sha256=b"b" * 64,
            ),
            id="frozen-sha",
        ),
        pytest.param(
            lambda: FrozenPolicy(
                policy=ContractPolicy(baseline=PolicyBaseline(sha256="a" * 64, format="docx")),
                canonical_sha256="b" * 64,
                assurance=b"local",
            ),
            id="frozen-assurance",
        ),
    ],
)
def test_policy_rejects_bytes_for_every_textual_field(
    build: Callable[[], object],
) -> None:
    with pytest.raises(ValidationError):
        build()


def test_policy_rejects_duplicate_expected_rule_ids() -> None:
    with pytest.raises(ValidationError):
        ContractPolicy(
            baseline=PolicyBaseline(sha256="a" * 64, format="pdf"),
            expect=[_expected_rule(), _expected_rule()],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("occurrences", True),
        ("min_similarity", "0.92"),
        ("min_margin", False),
    ],
)
def test_policy_rejects_ambiguous_raw_selector_scalars(field: str, value: object) -> None:
    selector = _selector().model_dump(mode="python")
    selector[field] = value

    with pytest.raises(ValidationError):
        ExpectedRule.model_validate(
            {
                "id": "payment-window",
                "selector": selector,
                "operation": {
                    "type": "exact_replace",
                    "before": "30 days",
                    "after": "45 days",
                },
            }
        )


@pytest.mark.parametrize("plugin_name", ["", "p" * 129])
def test_policy_bounds_required_plugin_names(plugin_name: str) -> None:
    with pytest.raises(ValidationError):
        ContractPolicy(
            baseline=PolicyBaseline(sha256="a" * 64, format="pdf"),
            required_plugins={
                plugin_name: PolicyPluginRequirement(version="1.0", distribution="example-plugin")
            },
        )


def test_policy_json_round_trip_is_strict_and_preserves_rule_order() -> None:
    first = _expected_rule("first-rule")
    second = _expected_rule("second-rule")
    policy = ContractPolicy(
        baseline=PolicyBaseline(sha256="a" * 64, format="docx"),
        expect=[first, second],
        allow=[AllowRule(selector=_selector(), kinds={"modified", "moved"})],
        protect={"money", "dates"},
    )

    restored = ContractPolicy.model_validate_json(policy.model_dump_json())

    assert restored == policy
    assert [rule.id for rule in restored.expect] == ["first-rule", "second-rule"]
    assert restored.allow[0].kinds == frozenset({"modified", "moved"})


def test_policy_collection_defaults_are_independent() -> None:
    first = ContractPolicy(baseline=PolicyBaseline(sha256="a" * 64, format="docx"))
    second = ContractPolicy(baseline=PolicyBaseline(sha256="b" * 64, format="pdf"))

    first.expect.append(_expected_rule())
    first.required_plugins["example"] = PolicyPluginRequirement(version="1", distribution="example")

    assert second.expect == []
    assert second.required_plugins == {}
