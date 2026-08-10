"""Deterministic contract verification facts and rule evaluation."""

from artifactdiff.verification.facts import diff_contracts
from artifactdiff.verification.models import (
    ClauseChange,
    ClauseChangeKind,
    ContractChangeSet,
    EntityChange,
    FeatureChange,
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
    RegionChange,
    finding_id,
)
from artifactdiff.verification.rules import evaluate_contract

__all__ = [
    "ClauseChange",
    "ClauseChangeKind",
    "ContractChangeSet",
    "EntityChange",
    "FeatureChange",
    "Finding",
    "FindingEvidence",
    "FindingOutcome",
    "RawVerdict",
    "RegionChange",
    "diff_contracts",
    "evaluate_contract",
    "finding_id",
]
