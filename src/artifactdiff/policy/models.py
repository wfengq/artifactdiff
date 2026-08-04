"""Strict, versioned data models for contract policies."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from artifactdiff.contract import ClauseSelector
from artifactdiff.models import StrictModel

PluginName = Annotated[str, Field(min_length=1, max_length=128)]
AllowKind = Literal["added", "removed", "modified", "moved"]


def _reject_ambiguous_selector_scalars(value: object) -> object:
    if isinstance(value, dict):
        occurrences = value.get("occurrences", 1)
        if isinstance(occurrences, bool) or not isinstance(occurrences, int):
            # Pydantic turns ValueError, but not TypeError, into ValidationError.
            raise ValueError(  # noqa: TRY004
                "selector occurrences must be an integer"
            )
        for field in ("min_similarity", "min_margin"):
            numeric = value.get(field, 0.0)
            if isinstance(numeric, bool) or not isinstance(numeric, (int, float)):
                raise ValueError(  # noqa: TRY004
                    f"selector {field} must be numeric"
                )
    return value


class EvidenceMode(StrEnum):
    MINIMAL = "minimal"
    FULL = "full"
    SEALED = "sealed"


class ExactReplace(StrictModel):
    type: Literal["exact_replace"] = "exact_replace"
    before: str = Field(min_length=1, max_length=10_000)
    after: str = Field(min_length=1, max_length=10_000)
    occurrences: StrictInt = Field(default=1, ge=1, le=100)


class ExpectedRule(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    selector: ClauseSelector
    operation: ExactReplace

    @field_validator("selector", mode="before")
    @classmethod
    def selector_scalars_are_unambiguous(cls, value: object) -> object:
        return _reject_ambiguous_selector_scalars(value)


class AllowRule(StrictModel):
    selector: ClauseSelector
    kinds: frozenset[AllowKind] = Field(min_length=1)

    @field_validator("selector", mode="before")
    @classmethod
    def selector_scalars_are_unambiguous(cls, value: object) -> object:
        return _reject_ambiguous_selector_scalars(value)


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


class VisualPolicy(StrictModel):
    explained_regions: Literal["pass"] = "pass"
    pagination_reflow: Literal["review", "fail"] = "review"
    protected_region_change: Literal["fail"] = "fail"
    on_unavailable: Literal["review", "fail"] = "review"
    layout_envelope_padding_points: float = Field(default=6.0, ge=0.0, le=72.0)

    @field_validator("layout_envelope_padding_points", mode="before")
    @classmethod
    def reject_ambiguous_padding(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            # Pydantic turns ValueError, but not TypeError, into ValidationError.
            raise ValueError("padding must be numeric")  # noqa: TRY004
        return value


class EvidencePolicy(StrictModel):
    mode: EvidenceMode = EvidenceMode.MINIMAL


class MetadataPolicy(StrictModel):
    non_business_change: Literal["review", "ignore"] = "review"


class PolicyBaseline(StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    format: Literal["pdf", "docx"]


class PolicyPluginRequirement(StrictModel):
    version: str = Field(min_length=1, max_length=128)
    distribution: str = Field(min_length=1, max_length=128)
    allow_network: StrictBool = False
    allow_model: StrictBool = False


class ContractPolicy(StrictModel):
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

    @model_validator(mode="after")
    def expected_rule_ids_are_unique(self) -> "ContractPolicy":
        identifiers = [rule.id for rule in self.expect]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("expected rule IDs must be unique")
        return self


class FrozenPolicy(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    policy: ContractPolicy
    canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assurance: Literal["local"] = "local"
