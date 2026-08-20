"""Verification and human-review command adapters."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli_support import (
    canonical_json,
    exit_for_error,
    interactive_signer,
    trust_store_from,
)
from artifactdiff.errors import ApprovalError, ArtifactDiffError, ReviewServerError, SessionError
from artifactdiff.verification import FindingOutcome
from artifactdiff.verification.service import VerificationOptions


def _exit_for_verdict(outcome: FindingOutcome) -> None:
    if outcome in {FindingOutcome.REVIEW, FindingOutcome.FAIL}:
        raise typer.Exit(1)


def verify(
    baseline: Path,
    candidate: Path,
    policy: Path = typer.Option(..., "--policy"),
    output: Path = typer.Option(Path("artifactdiff-review-bundle"), "--output", "-o"),
    session: Path | None = typer.Option(None, "--session"),
    archive_sign: str | None = typer.Option(None, "--archive-sign"),
    archive_key: Path | None = typer.Option(None, "--archive-key"),
    trust_store: Path | None = typer.Option(None, "--trust-store"),
    no_visual: bool = typer.Option(False, "--no-visual"),
    json_console: bool = typer.Option(False, "--json"),
) -> None:
    """Verify a contract change and write its immutable Review Bundle."""
    try:
        store = trust_store_from(trust_store)
        signer = None
        unsigned_application = ArtifactDiffApplication(trust_store=store)
        if unsigned_application.requires_verified_session(policy):
            if (
                session is None
                or archive_sign is None
                or archive_key is None
                or trust_store is None
            ):
                raise SessionError(
                    "verified policies require --session, --archive-sign, --archive-key, and --trust-store"
                )
            signer = interactive_signer(archive_sign, archive_key, store)
        app = ArtifactDiffApplication(trust_store=store, manifest_signer=signer)
        bundle = app.verify_change(
            baseline,
            candidate,
            policy,
            output,
            VerificationOptions(visual=not no_visual),
            session_path=session,
        )
        verification = app.verify_bundle(bundle)
    except ArtifactDiffError as error:
        exit_for_error(error)
    if json_console:
        typer.echo(
            canonical_json(
                {"bundle": str(bundle), "verification": verification.model_dump(mode="json")}
            )
        )
    else:
        typer.echo(str(bundle))
    # A newly created bundle has no approvals, so raw review/fail blocks immediately.
    try:
        _exit_for_verdict(app.effective_verdict(bundle).outcome)
    except ArtifactDiffError as error:
        exit_for_error(error)


def review(
    bundle: Path | None = typer.Argument(None),
    no_open: bool = typer.Option(False, "--no-open"),
    sign: str | None = typer.Option(None, "--sign"),
    key: Path | None = typer.Option(None, "--key"),
    trust_store: Path | None = typer.Option(None, "--trust-store"),
) -> None:
    """Open the authenticated local desk for one immutable Review Bundle."""
    try:
        if bundle is None:
            raise SessionError("review bundle is required")
        if (sign is None) != (key is None) or (sign is not None and trust_store is None):
            raise SessionError("--sign and --key require each other and --trust-store")
        store = trust_store_from(trust_store)
        application = ArtifactDiffApplication(trust_store=store)
        signing_provider = None
        if sign is not None and key is not None:
            from artifactdiff.review_web.signing_provider import (
                InteractiveEd25519SigningProvider,
            )

            signing_provider = InteractiveEd25519SigningProvider(application, sign, key, store)
        from artifactdiff.review_web import server as review_server
        from artifactdiff.review_web.app import ReviewContext

        try:
            server = review_server.serve_review(
                ReviewContext(application, "bundle", bundle, signing_provider),
                open_browser=not no_open,
            )
            try:
                server.thread.join()
            finally:
                server.shutdown()
        except ArtifactDiffError:
            raise
        except (OSError, RuntimeError):
            raise ReviewServerError("local review server operation failed") from None
    except ArtifactDiffError as error:
        exit_for_error(error)


def approve(
    bundle: Path,
    finding: str = typer.Option(..., "--finding"),
    reason: str = typer.Option(..., "--reason"),
    sign: str = typer.Option(..., "--sign"),
    key: Path = typer.Option(..., "--key"),
    trust_store: Path = typer.Option(..., "--trust-store"),
) -> None:
    """Append an explicit human approval to one review finding."""
    try:
        if not reason.strip():
            raise ApprovalError("approval reason must not be empty")
        if not sys.stdin.isatty():
            raise ApprovalError("finding approvals require an interactive terminal")
        store = trust_store_from(trust_store)
        event = ArtifactDiffApplication(trust_store=store).approve(
            bundle, finding, reason, signer=interactive_signer(sign, key, store)
        )
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(canonical_json(event.model_dump(mode="json")))
