"""Policy subcommands backed exclusively by :mod:`artifactdiff.application`."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import cast

import typer

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli_support import exit_for_error, interactive_signer, trust_store_from
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import ArtifactDiffError, PolicyValidationError

policy_app = typer.Typer(no_args_is_help=True)


def _required(value: str | None, label: str) -> str:
    if value is not None:
        return value
    if not sys.stdin.isatty():
        raise PolicyValidationError(f"{label} is required for non-interactive policy creation")
    return cast(str, typer.prompt(label))


@policy_app.command("create")
def create(
    baseline: Path,
    output: Path = typer.Option(..., "--output", "-o"),
    rule_id: str | None = typer.Option(None, "--rule-id"),
    clause: str | None = typer.Option(None, "--clause"),
    heading: str | None = typer.Option(None, "--heading"),
    anchor: str | None = typer.Option(None, "--anchor"),
    before: str | None = typer.Option(None, "--before"),
    after: str | None = typer.Option(None, "--after"),
    force_output: bool = typer.Option(False, "--force-output"),
    no_open: bool = typer.Option(False, "--no-open"),
    sign: str | None = typer.Option(None, "--sign"),
    key: Path | None = typer.Option(None, "--key"),
    trust_store: Path | None = typer.Option(None, "--trust-store"),
) -> None:
    """Draft one contract-safe exact replacement policy."""
    try:
        if output.exists() and not force_output:
            raise PolicyValidationError("policy output already exists; use --force-output")
        if any(value is not None for value in (sign, key, trust_store)) and not all(
            value is not None for value in (sign, key, trust_store)
        ):
            raise PolicyValidationError(
                "--sign, --key, and --trust-store must be supplied together"
            )
        store = trust_store_from(trust_store)
        application = ArtifactDiffApplication(trust_store=store)
        missing = (rule_id, clause, heading, anchor, before, after)
        if any(value is None for value in missing) and sys.stdin.isatty() and not no_open:
            from artifactdiff.review_web import server as review_server
            from artifactdiff.review_web.app import ReviewContext
            from artifactdiff.review_web.signing_provider import InteractiveEd25519SigningProvider

            signing_provider = (
                InteractiveEd25519SigningProvider(application, sign, key, store)
                if sign is not None and key is not None
                else None
            )

            server = review_server.serve_review(
                ReviewContext(
                    application,
                    "policy",
                    baseline,
                    signing_provider,
                    output_path=output,
                ),
                open_browser=True,
            )
            try:
                server.thread.join()
            finally:
                server.shutdown()
            if not output.is_file():
                raise PolicyValidationError("policy wizard closed without sealing an artifact")
            typer.echo(str(output.resolve()))
            return
        policy = application.draft_policy(
            baseline,
            ClauseSelector(
                clause_label=_required(clause, "clause"),
                heading=_required(heading, "heading"),
                anchor=_required(anchor, "anchor"),
            ),
            rule_id=_required(rule_id, "rule-id"),
            before=_required(before, "before"),
            after=_required(after, "after"),
        )
        application.write_policy(policy, output)
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(str(output.resolve()))


@policy_app.command("validate")
def validate(baseline: Path, policy: Path) -> None:
    """Validate a policy against its baseline contract."""
    try:
        application = ArtifactDiffApplication(trust_store=trust_store_from(None))
        checked = application.validate_policy(baseline, policy)
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(f"policy_sha256={checked.policy_sha256}")
    typer.echo(f"clause_id={checked.resolved_clause_id}")


@policy_app.command("seal")
def seal(
    baseline: Path,
    policy: Path,
    output: Path = typer.Option(..., "--output", "-o"),
    sign: str | None = typer.Option(None, "--sign"),
    key: Path | None = typer.Option(None, "--key"),
    trust_store: Path | None = typer.Option(None, "--trust-store"),
) -> None:
    """Freeze a local policy, optionally attaching a verified authorization."""
    try:
        store = trust_store_from(trust_store)
        application = ArtifactDiffApplication(trust_store=store)
        signer = None
        if sign is not None or key is not None or trust_store is not None:
            if sign is None or key is None or trust_store is None:
                raise PolicyValidationError(
                    "--sign, --key, and --trust-store must be supplied together"
                )
            signer = interactive_signer(sign, key, store)
        application.seal_policy(baseline, policy, output, signer=signer)
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(str(output.resolve()))
