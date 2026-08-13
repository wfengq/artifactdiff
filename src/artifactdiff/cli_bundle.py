"""Review Bundle verification and archive command adapters."""

from __future__ import annotations

from pathlib import Path

import typer

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli_support import canonical_json, exit_for_error, trust_store_from
from artifactdiff.errors import ArtifactDiffError, EvidenceError
from artifactdiff.policy.models import EvidenceMode
from artifactdiff.verification import FindingOutcome

bundle_app = typer.Typer(no_args_is_help=True)


@bundle_app.command("verify")
def verify(bundle: Path, trust_store: Path | None = typer.Option(None, "--trust-store")) -> None:
    """Independently verify a Review Bundle without disclosing contract text."""
    try:
        store = trust_store_from(trust_store)
        app = ArtifactDiffApplication(trust_store=store)
        verified = app.verify_bundle(bundle)
        if not verified.valid:
            raise EvidenceError("review bundle verification failed")
        effective = app.effective_verdict(bundle)
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(canonical_json(verified.model_dump(mode="json")))
    if effective.outcome in {FindingOutcome.REVIEW, FindingOutcome.FAIL}:
        raise typer.Exit(1)


@bundle_app.command("pack")
def pack(
    bundle: Path,
    output: Path,
    mode: EvidenceMode = typer.Option(..., "--mode"),
    recipient: list[str] = typer.Option([], "--recipient"),
) -> None:
    """Pack a minimal, full, or recipient-sealed evidence archive."""
    try:
        if mode is EvidenceMode.SEALED and not recipient:
            raise EvidenceError("sealed bundles require at least one recipient")
        result = ArtifactDiffApplication(trust_store=trust_store_from(None)).pack_bundle(
            bundle, output, mode=mode, recipients=tuple(recipient)
        )
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(str(result))
