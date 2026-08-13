"""Verified edit-session command adapter."""

from __future__ import annotations

from pathlib import Path

import typer

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli_support import exit_for_error, interactive_signer, trust_store_from
from artifactdiff.errors import ArtifactDiffError, SessionError
from artifactdiff.fs_safety import PathPolicy

session_app = typer.Typer(no_args_is_help=True)


@session_app.command("open")
def open_session(
    baseline: Path,
    policy: Path = typer.Option(..., "--policy"),
    output: Path = typer.Option(..., "--output"),
    sign: str = typer.Option(..., "--sign"),
    key: Path = typer.Option(..., "--key"),
    trust_store: Path = typer.Option(..., "--trust-store"),
) -> None:
    """Open a controlled candidate workspace for an authorized policy."""
    try:
        store = trust_store_from(trust_store)
        input_root = baseline.resolve().parent
        policy_root = policy.resolve().parent
        if policy_root != input_root:
            raise SessionError("baseline and sealed policy must share an input root")
        app = ArtifactDiffApplication(
            trust_store=store,
            path_policy=PathPolicy(
                input_roots=(input_root,), output_roots=(output.resolve().parent,)
            ),
        )
        session = app.open_verified_session(
            baseline, policy, output, session_signer=interactive_signer(sign, key, store)
        )
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(str(session.candidate_path.resolve()))
    typer.echo(session.session_id)
