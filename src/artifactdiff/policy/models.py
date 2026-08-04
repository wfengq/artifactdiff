"""Strict, versioned data models for contract policies."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from artifactdiff.contract import ClauseSelector
from artifactdiff.models import StrictModel

PluginName = Annotated[StrictStr, Field(min_length=1, max_length=128)]
AllowKind = Literal["added", "removed", "modified", "moved"]


def _require_text(value: object) -> object:
    if not isinstance(value, str):
        # Pydantic turns ValueError, but not TypeError, into ValidationError.
        raise ValueError("value must be text")  # noqa: TRY004
    return value


def _require_text_collection(value: object) -> object:
    if not isinstance(value, (list, tuple, set, frozenset)) or any(
        not isinstance(item, str) for item in value
    ):
        raise ValueError("collection values must be text")
    return value


class PolicyModel(StrictModel):
    """Policy base that revalidates prebuilt nested model instances."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")


class EvidenceMode(StrEnum):
    MINIMAL = "minimal"
    FULL = "full"
    SEALED = "sealed"


class ExactReplace(PolicyModel):
    type: Literal["exact_replace"] = "exact_replace"
    before: StrictStr = Field(min_length=1, max_length=10_000)
    after: StrictStr = Field(min_length=1, max_length=10_000)
    occurrences: StrictInt = Field(default=1, ge=1, le=100)

    _type_is_text = field_validator("type", mode="before")(_require_text)


class ExpectedRule(PolicyModel):
    id: StrictStr = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    selector: ClauseSelector
    operation: ExactReplace


class AllowRule(PolicyModel):
    selector: ClauseSelector
    kinds: frozenset[AllowKind] = Field(min_length=1)

    _kinds_are_text = field_validator("kinds", mode="before")(_require_text_collection)


class ProtectedTarget(StrEnum):
    PARTIES = "parties"
    MONEY = "money"
    CURRENCY = "currency"
    DATES = "dates"
    DURATIONS = "durations"
    PERCENTAGES = "percentages"
    HEADERS = "headers"
    FOOTERS = "footers"
    SIGNATURES = "signatures"
    SEALS = "seals"
    ATTACHMENTS = "attachments"


class VisualPolicy(PolicyModel):
    explained_regions: Literal["pass"] = "pass"
    pagination_reflow: Literal["review", "fail"] = "review"
    protected_region_change: Literal["fail"] = "fail"
    on_unavailable: Literal["review", "fail"] = "review"
    layout_envelope_padding_points: float = Field(default=6.0, ge=0.0, le=72.0)

    _outcomes_are_text = field_validator(
        "explained_regions",
        "pagination_reflow",
        "protected_region_change",
        "on_unavailable",
        mode="before",
    )(_require_text)

    @field_validator("layout_envelope_padding_points", mode="before")
    @classmethod
    def reject_ambiguous_padding(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            # Pydantic turns ValueError, but not TypeError, into ValidationError.
            raise ValueError("padding must be numeric")  # noqa: TRY004
        return value


class EvidencePolicy(PolicyModel):
    mode: EvidenceMode = EvidenceMode.MINIMAL

    _mode_is_text = field_validator("mode", mode="before")(_require_text)


class MetadataPolicy(PolicyModel):
    non_business_change: Literal["review", "ignore"] = "review"

    _outcome_is_text = field_validator("non_business_change", mode="before")(_require_text)


class PolicyBaseline(PolicyModel):
    sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    format: Literal["pdf", "docx"]

    _format_is_text = field_validator("format", mode="before")(_require_text)


class PolicyPluginRequirement(PolicyModel):
    version: StrictStr = Field(min_length=1, max_length=128)
    distribution: StrictStr = Field(min_length=1, max_length=128)
    allow_network: StrictBool = False
    allow_model: StrictBool = False


class ContractPolicy(PolicyModel):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["contract-safe"] = "contract-safe"
    profile_version: Literal["1.0"] = "1.0"
    baseline: PolicyBaseline
    expect: list[ExpectedRule] = Field(default_factory=list, max_length=100)
    allow: list[AllowRule] = Field(default_factory=list, max_length=100)
    protect: frozenset[ProtectedTarget] = Field(default_factory=lambda: frozenset(ProtectedTarget))
    visual: VisualPolicy = Field(default_factory=VisualPolicy)
    metadata: MetadataPolicy = Field(default_factory=MetadataPolicy)
    evidence: EvidencePolicy = Field(default_factory=EvidencePolicy)
    required_plugins: dict[PluginName, PolicyPluginRequirement] = Field(
        default_factory=dict, max_length=100
    )

    _versions_are_text = field_validator(
        "schema_version", "profile", "profile_version", mode="before"
    )(_require_text)
    _protected_targets_are_text = field_validator("protect", mode="before")(
        _require_text_collection
    )

    @field_validator("expect", "allow", mode="before")
    @classmethod
    def rule_collections_are_ordered(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            raise ValueError("rule collections must be ordered")  # noqa: TRY004
        return value

    @model_validator(mode="after")
    def expected_rule_ids_are_unique(self) -> "ContractPolicy":
        identifiers = [rule.id for rule in self.expect]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("expected rule IDs must be unique")
        return self


class FrozenPolicy(PolicyModel):
    schema_version: Literal["1.0"] = "1.0"
    policy: ContractPolicy
    canonical_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    assurance: Literal["local"] = "local"

    _labels_are_text = field_validator("schema_version", "assurance", mode="before")(_require_text)
