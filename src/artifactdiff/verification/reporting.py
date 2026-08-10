"""Atomic, portable raw verification-report serialization."""

import json
from dataclasses import dataclass
from pathlib import Path

from artifactdiff.errors import InputValidationError
from artifactdiff.models import ComparisonResult
from artifactdiff.policy.models import FrozenPolicy
from artifactdiff.verification.models import ContractChangeSet, RawVerdict
from artifactdiff.visual import VisualAssets
from artifactdiff.visual_service import VisualComparison

MAX_VERIFICATION_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerificationRun:
    """Raw verdict, factual comparison, and the resulting JSON artifact."""

    result: RawVerdict
    facts: ContractChangeSet
    comparison: ComparisonResult
    json_path: Path
    visual_assets: dict[str, VisualAssets]


def write_verification_run(
    verdict: RawVerdict,
    facts: ContractChangeSet,
    visual: VisualComparison,
    output_dir: Path,
    *,
    comparison: ComparisonResult,
    frozen_policy: FrozenPolicy,
) -> VerificationRun:
    """Atomically write one deterministic, bounded verification JSON artifact."""
    checked_comparison = ComparisonResult.model_validate(comparison)
    checked_facts = ContractChangeSet.model_validate(facts)
    checked_verdict = RawVerdict.model_validate(verdict)
    checked_frozen = FrozenPolicy.model_validate(frozen_policy)
    payload = {
        "schema_version": "1.0",
        "frozen_policy": {
            "canonical_sha256": checked_frozen.canonical_sha256,
            "assurance": checked_frozen.assurance,
        },
        "sources": {
            "baseline": checked_comparison.before.model_dump(mode="json"),
            "candidate": checked_comparison.after.model_dump(mode="json"),
        },
        "neutral_facts": checked_facts.model_dump(mode="json"),
        "comparison": checked_comparison.model_dump(mode="json"),
        "raw_verdict": checked_verdict.model_dump(mode="json"),
        "environment": {
            "engine_version": checked_comparison.engine_version,
            "visual_available": visual.available,
        },
        "warnings": list(visual.warnings),
    }
    contents = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(contents) > MAX_VERIFICATION_BYTES:
        raise InputValidationError("verification report exceeds 10 MiB limit")

    destination = output_dir.expanduser().resolve() / "verification.json"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(contents)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return VerificationRun(
        result=checked_verdict,
        facts=checked_facts,
        comparison=checked_comparison,
        json_path=destination,
        visual_assets=visual.assets,
    )
