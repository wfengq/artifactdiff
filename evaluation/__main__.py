"""Command line entry point: ``python -m evaluation``."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from evaluation.models import Format
from evaluation.report import (
    RunMetadata,
    artifactdiff_version,
    build_summary,
    current_git_commit,
    headline,
    write_report,
)
from evaluation.runner import run_cases
from evaluation.sources import CUAD_SHA256, fetch_cuad, load_cuad, load_synthetic

DEFAULT_DATA_DIR = Path(__file__).parent / "data"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m evaluation", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    fetch = commands.add_parser("fetch-cuad", help="download, verify and extract CUAD v1")
    fetch.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    fetch.add_argument("--archive", type=Path, help="use an already downloaded CUAD_v1.zip")

    run = commands.add_parser("run", help="run the benchmark and write a report")
    run.add_argument("--source", choices=("synthetic", "cuad"), required=True)
    run.add_argument("--formats", default="docx,pdf")
    run.add_argument("--limit", type=int)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    run.add_argument("--case-timeout", type=float, default=120.0)
    run.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    run.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "fetch-cuad":
        text_dir = fetch_cuad(arguments.data_dir, archive=arguments.archive)
        print(text_dir)
        return 0

    output: Path = arguments.output
    if output.exists() and any(output.iterdir()):
        print(f"error: output directory {output} must be empty or absent", file=sys.stderr)
        return 2
    try:
        formats = [Format(name.strip()) for name in arguments.formats.split(",") if name.strip()]
    except ValueError:
        print(f"error: unknown format in {arguments.formats!r}", file=sys.stderr)
        return 2

    if arguments.source == "cuad":
        text_dir = arguments.data_dir / "generated" / "cuad"
        if not text_dir.is_dir():
            print(
                f"error: CUAD data not found under {text_dir}; "
                "run `python -m evaluation fetch-cuad` first",
                file=sys.stderr,
            )
            return 2
        contracts = load_cuad(text_dir, limit=arguments.limit, seed=arguments.seed)
    else:
        contracts = load_synthetic()[: arguments.limit]

    # Record what is being measured before the run: HEAD may move while it executes.
    git_commit = current_git_commit()
    version = artifactdiff_version()
    with tempfile.TemporaryDirectory(prefix="artifactdiff-eval-") as workdir:
        run = run_cases(
            contracts,
            formats,
            seed=arguments.seed,
            workers=arguments.workers,
            case_timeout=arguments.case_timeout,
            workdir=Path(workdir),
        )
    metadata = RunMetadata(
        source=arguments.source,
        cuad_sha256=CUAD_SHA256 if arguments.source == "cuad" else None,
        artifactdiff_version=version,
        git_commit=git_commit,
        seed=arguments.seed,
        limit=arguments.limit,
        formats=tuple(fmt.value for fmt in formats),
        options={"visual": False, "case_timeout": arguments.case_timeout},
    )
    write_report(output, run, metadata)
    summary = build_summary(run, metadata)
    print(headline(summary))
    print(output / "report.md")
    # Errors leave the false-pass denominator, so a run with errors must not look clean.
    return 1 if summary["counts"]["errors"] else 0  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
