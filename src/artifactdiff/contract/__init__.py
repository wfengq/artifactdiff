"""Public interfaces for deterministic contract analysis."""

from artifactdiff.contract.headings import extract_independent_headings
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
from artifactdiff.contract.service import inspect_contract, load_contract

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
    "extract_independent_headings",
    "inspect_contract",
    "load_contract",
    "resolve_baseline",
    "resolve_candidate",
]
