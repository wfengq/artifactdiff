"""Metrics and JSON/Markdown reports for an evaluation run."""

from __future__ import annotations

import json
import math
import statistics
import subprocess
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

from evaluation.models import CaseResult, Expectation
from evaluation.mutations import OPERATORS
from evaluation.runner import RunResult
from evaluation.sources import CUAD_ATTRIBUTION

_BUCKETS = ("<1k", "1-2k", "2-5k", ">5k")
_GROUPS = {spec.name: spec.group for spec in OPERATORS}


@dataclass(frozen=True)
class RunMetadata:
    source: str
    cuad_sha256: str | None
    artifactdiff_version: str
    git_commit: str | None
    seed: int
    limit: int | None
    formats: tuple[str, ...]
    options: dict[str, object]


def artifactdiff_version() -> str:
    return importlib_metadata.version("artifactdiff")


def current_git_commit() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
    margin /= denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def clause_bucket(chars: int) -> str:
    if chars < 1000:
        return "<1k"
    if chars < 2000:
        return "1-2k"
    if chars < 5000:
        return "2-5k"
    return ">5k"


def _rate(count: int, total: int) -> dict[str, object]:
    lo, hi = wilson_interval(count, total)
    rate = count / total if total else 0.0
    return {"count": count, "total": total, "rate": rate, "ci95": [lo, hi]}


def _false_pass(rows: list[CaseResult]) -> dict[str, object]:
    evaluated = [r for r in rows if r.expectation is Expectation.BLOCK and r.error is None]

    def grouped(field: str) -> dict[str, object]:
        keys = sorted({_field(r, field) for r in evaluated})
        return {
            key: _rate(
                sum(r.false_pass for r in evaluated if _field(r, field) == key),
                sum(1 for r in evaluated if _field(r, field) == key),
            )
            for key in keys
        }

    return {
        "overall": _rate(sum(r.false_pass for r in evaluated), len(evaluated)),
        "by_format": grouped("format"),
        "by_operator": grouped("operator"),
        "by_group": grouped("group"),
    }


def _field(row: CaseResult, field: str) -> str:
    if field == "format":
        return row.key.format
    if field == "operator":
        return row.key.operator
    return _GROUPS.get(row.key.operator, "unknown")


def _acceptance(rows: list[CaseResult]) -> dict[str, object]:
    accept = [r for r in rows if r.expectation is Expectation.ACCEPT]
    reasons: Counter[str] = Counter()
    for row in accept:
        if row.error is not None:
            reasons["runner-error"] += 1
        elif not row.accepted:
            reasons.update(row.nonpass_rule_ids)
    buckets: dict[str, object] = {}
    for bucket in _BUCKETS:
        members = [
            r
            for r in accept
            if r.edited_clause_chars is not None and clause_bucket(r.edited_clause_chars) == bucket
        ]
        accepted = sum(r.accepted for r in members)
        lo, hi = wilson_interval(accepted, len(members))
        buckets[bucket] = {
            "accepted": accepted,
            "total": len(members),
            "rate": accepted / len(members) if members else 0.0,
            "ci95": [lo, hi],
        }
    accepted = sum(r.accepted for r in accept)
    lo, hi = wilson_interval(accepted, len(accept))
    return {
        "accepted": accepted,
        "total": len(accept),
        "rate": accepted / len(accept) if accept else 0.0,
        "ci95": [lo, hi],
        "false_block_reasons": _ranked(reasons),
        "by_clause_bucket": buckets,
    }


def _ranked(counter: Counter[str]) -> list[list[object]]:
    return [[key, count] for key, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))]


def build_summary(run: RunResult, metadata: RunMetadata) -> dict[str, object]:
    rows = run.results
    evaluated_blocks = [r for r in rows if r.expectation is Expectation.BLOCK and r.error is None]
    blocked_split = {
        name: {
            "fail": sum(
                1 for r in evaluated_blocks if r.key.operator == name and r.text_verdict == "fail"
            ),
            "review": sum(
                1 for r in evaluated_blocks if r.key.operator == name and r.text_verdict == "review"
            ),
        }
        for name in sorted({r.key.operator for r in evaluated_blocks})
    }
    prepared = {(r.key.source, r.key.contract_id, r.key.format) for r in rows} | {
        (key.source, key.contract_id, key.format) for key, _ in run.not_applicable
    }
    total_prepared = len(prepared) + len(run.draft_failures)
    applicable = Counter(r.key.operator for r in rows)
    missing = Counter(key.operator for key, _ in run.not_applicable)
    durations = sorted(r.duration_s for r in rows if r.error is None)
    return {
        "metadata": asdict(metadata),
        "counts": {
            "cases": len(rows),
            "errors": sum(1 for r in rows if r.error is not None),
            "draft_failures": len(run.draft_failures),
            "not_applicable": len(run.not_applicable),
            "pdf_replacements": run.pdf_replacements,
        },
        "false_pass": _false_pass(rows),
        "blocked_split": blocked_split,
        "acceptance": _acceptance(rows),
        "draftability": {
            "draftable": len(prepared),
            "total": total_prepared,
            "rate": len(prepared) / total_prepared if total_prepared else 0.0,
            "reasons": _ranked(Counter(failure.reason for failure in run.draft_failures)),
        },
        "applicability": {
            name: {"applicable": applicable[name], "not_applicable": missing[name]}
            for name in sorted(set(applicable) | set(missing))
        },
        "duration_s": {
            "median": statistics.median(durations) if durations else 0.0,
            "p95": durations[max(0, math.ceil(0.95 * len(durations)) - 1)] if durations else 0.0,
        },
    }


def write_report(output: Path, run: RunResult, metadata: RunMetadata) -> None:
    output.mkdir(parents=True, exist_ok=True)
    rows = sorted(run.results, key=lambda result: result.key)
    (output / "results.jsonl").write_text(
        "".join(json.dumps(r.to_json(), sort_keys=True, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8",
    )
    summary = build_summary(run, metadata)
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output / "report.md").write_text(render_markdown(summary, metadata), encoding="utf-8")


def headline(summary: Mapping[str, Any]) -> str:
    overall = summary["false_pass"]["overall"]
    lo, hi = overall["ci95"]
    draftability = summary["draftability"]
    return (
        f"False passes: {overall['count']}/{overall['total']} "
        f"({overall['rate']:.2%}, 95% CI {lo:.2%}–{hi:.2%}); "
        f"errors: {summary['counts']['errors']}; "
        f"not draftable: {draftability['total'] - draftability['draftable']}"
        f"/{draftability['total']}"
    )


def _table(header: tuple[str, ...], rows: list[tuple[object, ...]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return lines


def _pct(entry: Mapping[str, Any]) -> str:
    lo, hi = entry["ci95"]
    return f"{entry['rate']:.2%} ({lo:.2%}–{hi:.2%})"


def render_markdown(summary: Mapping[str, Any], metadata: RunMetadata) -> str:
    false_pass = summary["false_pass"]
    acceptance = summary["acceptance"]
    draftability = summary["draftability"]
    counts = summary["counts"]
    lines = [
        f"# ArtifactDiff evaluation: {metadata.source}",
        "",
        f"- ArtifactDiff {metadata.artifactdiff_version}, commit `{metadata.git_commit}`",
        f"- Formats: {', '.join(metadata.formats)}; seed {metadata.seed}; limit {metadata.limit}",
        f"- Options: `{json.dumps(metadata.options, sort_keys=True)}`",
    ]
    if metadata.cuad_sha256:
        lines.append(f"- CUAD archive SHA-256: `{metadata.cuad_sha256}`")
    lines += [
        f"- Cases: {counts['cases']}; errors: {counts['errors']}; not applicable: "
        f"{counts['not_applicable']}; PDF replaced characters: {counts['pdf_replacements']}",
        "",
        f"**{headline(summary)}**",
        "",
        f"**Authorized edits accepted: {acceptance['accepted']}/{acceptance['total']} "
        f"({_pct(acceptance)})**",
        "",
        f"**Draftable contracts: {draftability['draftable']}/{draftability['total']} "
        f"({draftability['rate']:.2%})**",
        "",
        "## False passes by operator",
        "",
    ]
    by_operator = false_pass["by_operator"]
    split = summary["blocked_split"]
    lines += _table(
        ("Operator", "Group", "False passes", "Rate (95% CI)", "Blocked FAIL", "Blocked REVIEW"),
        [
            (
                name,
                _GROUPS.get(name, "unknown"),
                f"{entry['count']}/{entry['total']}",
                _pct(entry),
                split.get(name, {}).get("fail", 0),
                split.get(name, {}).get("review", 0),
            )
            for name, entry in by_operator.items()
        ],
    )
    lines += ["", "## False passes by format", ""]
    lines += _table(
        ("Format", "False passes", "Rate (95% CI)"),
        [(n, f"{e['count']}/{e['total']}", _pct(e)) for n, e in false_pass["by_format"].items()],
    )
    lines += ["", "## Why authorized edits were blocked", ""]
    lines += _table(("Rule", "Cases"), [tuple(row) for row in acceptance["false_block_reasons"]])
    lines += ["", "## Acceptance by edited-clause length", ""]
    buckets = acceptance["by_clause_bucket"]
    lines += _table(
        ("Clause length", "Accepted", "Rate (95% CI)"),
        [(b, f"{e['accepted']}/{e['total']}", _pct(e)) for b, e in buckets.items()],
    )
    lines += ["", "## Draft failures", ""]
    lines += _table(("Reason", "Contracts"), [tuple(row) for row in draftability["reasons"]])
    lines += [
        "",
        "## Limitations",
        "",
        "- Visual evidence was disabled (`visual=False`). Verdicts are text verdicts: the",
        "  `contract-safe.visual.unavailable` finding is ignored, which can only add passes.",
        "- Runner errors and timeouts are excluded from false-pass denominators and count as",
        "  not accepted for authorized edits.",
    ]
    if metadata.source == "cuad":
        lines += ["", "## Attribution", "", CUAD_ATTRIBUTION]
    return "\n".join(lines) + "\n"
