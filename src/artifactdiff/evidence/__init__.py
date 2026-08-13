"""Evidence privacy, collection, and archive interfaces."""

from artifactdiff.evidence.age_cli import AgeCliProvider
from artifactdiff.evidence.archive import extract_bundle_archive, pack_bundle
from artifactdiff.evidence.collector import collect_evidence
from artifactdiff.evidence.models import EvidenceIndex, EvidenceItem, EvidenceKind

__all__ = [
    "AgeCliProvider",
    "EvidenceIndex",
    "EvidenceItem",
    "EvidenceKind",
    "collect_evidence",
    "extract_bundle_archive",
    "pack_bundle",
]
