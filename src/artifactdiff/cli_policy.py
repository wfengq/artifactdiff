"""Policy subcommands backed exclusively by :mod:`artifactdiff.application`."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli_support import exit_for_error, interactive_signer, trust_store_from
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import ArtifactDiffError, PolicyValidationError
from artifactdiff.policy import policy_digest

policy_app = typer.Typer(no_args_is_help=True)


def _required(value: str | None, label: str) -> str:
    if value is not None:
        return value
    if not sys.stdin.isatty():
        raise PolicyValidationError(f"{label} is required for non-interactive policy creation")
    return typer.prompt(label)


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
) -> None:
    """Draft one contract-safe exact replacement policy."""
    try:
        if output.exists() and not force_output:
            raise PolicyValidationError("policy output already exists; use --force-output")
        application = ArtifactDiffApplication(trust_store=trust_store_from(None))
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
        if output.exists():
            output.unlink()
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
        contract = application.inspect_contract(baseline)
        matching = [
            clause["id"]
            for clause in contract["clauses"]
            if isinstance(clause, dict)
            and clause.get("fingerprint") == checked.expect[0].selector.baseline_fingerprint
        ]
    except ArtifactDiffError as error:
        exit_for_error(error)
    typer.echo(f"policy_sha256={policy_digest(checked)}")
    typer.echo(f"clause_id={matching[0] if len(matching) == 1 else 'unresolved'}")


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
