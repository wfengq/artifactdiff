"""Services for loading and inspecting deterministic contract IR."""

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from artifactdiff.contract.analyzer import analyze_contract
from artifactdiff.contract.models import ContractDocument
from artifactdiff.errors import InputValidationError
from artifactdiff.formats import adapter_for
from artifactdiff.limits import validate_source
from artifactdiff.models import DocumentSnapshot


def load_contract(
    path: Path, *, render: bool, force: bool, workdir: Path
) -> tuple[DocumentSnapshot, ContractDocument]:
    """Load one validated source and analyze its deterministic contract structure."""
    source = validate_source(path, force=force)
    snapshot = adapter_for(source).load(
        source, render=render, workdir=workdir, force=force
    )
    return snapshot, analyze_contract(snapshot)


def inspect_contract(
    path: Path,
    *,
    force: bool = False,
    require_absolute: bool = False,
    max_clauses: int = 100,
) -> dict[str, object]:
    """Return bounded, JSON-serializable contract IR for one source."""
    if not 0 <= max_clauses <= 1000:
        raise InputValidationError("max_clauses must be between 0 and 1000")
    source = validate_source(path, force=force, require_absolute=require_absolute)
    with TemporaryDirectory(prefix="artifactdiff-contract-") as temporary:
        _, contract = load_contract(
            source,
            render=False,
            force=force,
            workdir=Path(temporary),
        )
    payload = contract.model_dump(mode="json")
    payload["clauses"] = payload["clauses"][:max_clauses]
    payload["truncated_clauses"] = len(contract.clauses) > max_clauses
    return cast(dict[str, object], payload)
