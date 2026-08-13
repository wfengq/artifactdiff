"""Command-line interface for local ArtifactDiff workflows."""

import json
from pathlib import Path
from typing import NoReturn

import typer

from artifactdiff.cli_bundle import bundle_app
from artifactdiff.cli_policy import policy_app
from artifactdiff.cli_review import approve, review, verify
from artifactdiff.cli_session import session_app
from artifactdiff.errors import ArtifactDiffError
from artifactdiff.service import CompareOptions, compare_documents, inspect_document

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
app.add_typer(policy_app, name="policy")
app.add_typer(session_app, name="session")
app.add_typer(bundle_app, name="bundle")


def _exit_for_error(error: ArtifactDiffError) -> NoReturn:
    typer.echo(f"ArtifactDiff error: {error}", err=True)
    raise typer.Exit(2) from None


@app.command()
def compare(
    before: Path,
    after: Path,
    output: Path = typer.Option(Path("artifactdiff-report"), "--output", "-o"),
    no_visual: bool = typer.Option(False, "--no-visual"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change"),
    force: bool = typer.Option(False, "--force"),
    pixel_threshold: int = typer.Option(16, min=0, max=255),
    tile_size: int = typer.Option(32, min=8, max=256),
    json_console: bool = typer.Option(False, "--json"),
) -> None:
    """Compare two local PDF or DOCX files and write offline reports."""
    try:
        run = compare_documents(
            before,
            after,
            output,
            options=CompareOptions(
                visual=not no_visual,
                force=force,
                pixel_threshold=pixel_threshold,
                tile_size=tile_size,
            ),
        )
    except ArtifactDiffError as error:
        _exit_for_error(error)

    if json_console:
        typer.echo(run.result.model_dump_json())
    else:
        typer.echo(f"{run.result.status}: {run.html_path}")
    if fail_on_change and run.result.status in {"changed", "partial"}:
        raise typer.Exit(1)


@app.command("inspect")
def inspect_command(
    path: Path,
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Print a bounded JSON structural summary for a local PDF or DOCX file."""
    try:
        result = inspect_document(path, force=force, max_blocks=100)
    except ArtifactDiffError as error:
        _exit_for_error(error)

    typer.echo(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


app.command()(verify)
app.command()(review)
app.command()(approve)
