"""Strict signed finding-decision and effective-verdict models."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, StrictInt, StrictStr, model_validator

from artifactdiff.models import StrictModel
from artifactdiff.trust import SignatureEnvelope
from artifactdiff.verification import FindingOutcome

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ReviewModel(StrictModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always", strict=True)


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalEvent(ReviewModel):
    schema_version: Literal["1.0"] = "1.0"
    event_type: Literal["finding_decision"] = "finding_decision"
    sequence: StrictInt = Field(ge=1)
    verification_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    previous_event_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    finding_id: StrictStr = Field(pattern=r"^finding-[0-9a-f]{24}$")
    decision: ApprovalDecision
    reason: StrictStr = Field(min_length=3, max_length=2000)
    signature: SignatureEnvelope


class EffectiveVerdict(ReviewModel):
    raw_outcome: FindingOutcome
    outcome: FindingOutcome
    approved_finding_ids: list[StrictStr]
    remaining_review_finding_ids: list[StrictStr]
    fail_finding_ids: list[StrictStr]
    event_chain_head: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def finding_sets_are_disjoint_sorted_and_unique(self) -> EffectiveVerdict:
        groups = (
            self.approved_finding_ids,
            self.remaining_review_finding_ids,
            self.fail_finding_ids,
        )
        if any(group != sorted(group) or len(group) != len(set(group)) for group in groups):
            raise ValueError("effective-verdict finding IDs must be sorted and unique")
        if (
            set(groups[0]) & set(groups[1])
            or set(groups[0]) & set(groups[2])
            or set(groups[1]) & set(groups[2])
        ):
            raise ValueError("effective-verdict finding sets must be disjoint")
        return self
