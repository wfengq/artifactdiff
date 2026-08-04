"""Public interfaces for deterministic contract analysis."""

from artifactdiff.contract.language import detect_language
from artifactdiff.contract.models import (
    ClauseLabel,
    ContractClause,
    ContractDocument,
    EntityKind,
    EvidenceRef,
    LanguageKind,
    LanguageProfile,
    ProtectedEntity,
    ProtectedRegion,
    ProtectedRegionKind,
)
from artifactdiff.contract.selectors import (
    ClauseSelector,
    SelectorMatch,
    SelectorResolution,
    SelectorResolutionStatus,
    resolve_baseline,
    resolve_candidate,
)

__all__ = [
    "ClauseLabel",
    "ClauseSelector",
    "ContractClause",
    "ContractDocument",
    "EntityKind",
    "EvidenceRef",
    "LanguageKind",
    "LanguageProfile",
    "ProtectedEntity",
    "ProtectedRegion",
    "ProtectedRegionKind",
    "SelectorMatch",
    "SelectorResolution",
    "SelectorResolutionStatus",
    "detect_language",
    "resolve_baseline",
    "resolve_candidate",
]
