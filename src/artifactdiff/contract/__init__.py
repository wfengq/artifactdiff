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

__all__ = [
    "ClauseLabel",
    "ContractClause",
    "ContractDocument",
    "EntityKind",
    "EvidenceRef",
    "LanguageKind",
    "LanguageProfile",
    "ProtectedEntity",
    "ProtectedRegion",
    "ProtectedRegionKind",
    "detect_language",
]
