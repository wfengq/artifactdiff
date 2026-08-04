"""Stdio MCP adapter for ArtifactDiff application services."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from artifactdiff.errors import ArtifactDiffError, InputValidationError
from artifactdiff.limits import validate_source
from artifactdiff.models import SourceDescriptor
from artifactdiff.service import (
    CompareOptions,
    ComparisonRun,
    compare_documents,
    inspect_document,
)

mcp = FastMCP("ArtifactDiff")


def _absolute_output_dir(output_dir: str | None, before: Path, after: Path) -> Path:
    if output_dir is not None:
        destination = Path(output_dir)
        if not destination.is_absolute():
            raise InputValidationError(f"Output directory must be absolute: {output_dir}")
        return destination.expanduser().resolve()

    before_hash = SourceDescriptor.from_path(before).sha256[:12]
    after_hash = SourceDescriptor.from_path(after).sha256[:12]
    return (Path.cwd() / "artifactdiff-reports" / f"{before_hash}-{after_hash}").resolve()


def _bounded_comparison_response(run: ComparisonRun) -> dict[str, object]:
    changes = run.result.changes[:20]
    reports = {
        "json": str(run.json_path.resolve()),
        "html": str(run.html_path.resolve()) if run.html_path is not None else None,
    }
    return {
        "ok": True,
        "schema_version": run.result.schema_version,
        "status": run.result.status,
        "summary": run.result.summary.model_dump(mode="json"),
        "warnings": list(run.result.warnings),
        "changes": [change.model_dump(mode="json") for change in changes],
        "truncated_changes": len(run.result.changes) > len(changes),
        "reports": reports,
    }


@mcp.tool(name="compare_documents")
async def compare_documents_tool(
    before_path: str,
    after_path: str,
    output_dir: str | None = None,
    visual: bool = True,
    force: bool = False,
) -> dict[str, object]:
    """Compare two absolute local document paths and return a bounded result."""
    try:
        before = validate_source(Path(before_path), force=force, require_absolute=True)
        after = validate_source(Path(after_path), force=force, require_absolute=True)
        destination = _absolute_output_dir(output_dir, before, after)
        run = compare_documents(
            before,
            after,
            destination,
            options=CompareOptions(visual=visual, force=force),
        )
        return _bounded_comparison_response(run)
    except ArtifactDiffError as error:
        return {"ok": False, "error_type": type(error).__name__, "error": str(error)}


@mcp.tool(name="inspect_document")
async def inspect_document_tool(path: str, force: bool = False) -> dict[str, object]:
    """Inspect an absolute local document path and return at most 100 blocks."""
    try:
        inspection = inspect_document(
            Path(path),
            force=force,
            require_absolute=True,
            max_blocks=100,
        )
        return {"ok": True, **inspection}
    except ArtifactDiffError as error:
        return {"ok": False, "error_type": type(error).__name__, "error": str(error)}


def main() -> None:
    """Run the ArtifactDiff MCP server over standard input/output."""
    mcp.run(transport="stdio")
