"""Execute evaluation cases in isolated, parallel, time-boxed workers."""

from __future__ import annotations

import multiprocessing
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.trust import TrustStore
from artifactdiff.verification.service import VerificationOptions
from evaluation.models import (
    VISUAL_UNAVAILABLE_RULE,
    CaseKey,
    CaseResult,
    DraftFailure,
    Expectation,
    Format,
    NotApplicable,
    SourceContract,
    text_verdict,
)
from evaluation.mutations import OPERATORS, operator_rng
from evaluation.render import render
from evaluation.targets import PreparedContract, prepare, prepared_dir


@dataclass(frozen=True)
class CaseJob:
    key: CaseKey
    expectation: Expectation
    prepared: PreparedContract
    candidate: tuple[str, ...]
    workdir: Path


@dataclass(frozen=True)
class RunResult:
    results: list[CaseResult]
    draft_failures: list[DraftFailure]
    not_applicable: list[tuple[CaseKey, str]]
    pdf_replacements: int


def execute_case(job: CaseJob) -> CaseResult:
    """Render one candidate and verify it against the prepared sealed policy."""
    started = time.perf_counter()
    prepared = job.prepared
    job.workdir.mkdir(parents=True, exist_ok=True)
    candidate = job.workdir / f"candidate.{prepared.format.value}"
    render(job.candidate, candidate, fmt=prepared.format, language=prepared.contract.language)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    bundle = application.verify_change(
        prepared.baseline_path,
        candidate,
        prepared.sealed_policy_path,
        job.workdir / "bundle",
        VerificationOptions(visual=False),
    )
    findings = [(item.rule_id, item.outcome.value) for item in application.list_findings(bundle)]
    return CaseResult(
        key=job.key,
        expectation=job.expectation,
        text_verdict=text_verdict(findings),
        raw_outcome=application.effective_verdict(bundle).raw_outcome.value,
        nonpass_rule_ids=tuple(
            sorted(
                {
                    rule_id
                    for rule_id, outcome in findings
                    if outcome != "pass" and rule_id != VISUAL_UNAVAILABLE_RULE
                }
            )
        ),
        edited_clause_chars=prepared.edited_clause_chars,
        baseline_clause_count=prepared.baseline_clause_count,
        duration_s=round(time.perf_counter() - started, 3),
        error=None,
    )


def run_cases(
    contracts: Sequence[SourceContract],
    formats: Sequence[Format],
    *,
    seed: int,
    workers: int,
    case_timeout: float,
    workdir: Path,
    case_fn: Callable[[CaseJob], CaseResult] | None = None,
) -> RunResult:
    prepared, draft_failures = _prepare_all(contracts, formats, workers, case_timeout, workdir)
    jobs: list[CaseJob] = []
    not_applicable: list[tuple[CaseKey, str]] = []
    for item in prepared:
        contract = item.contract
        for spec in OPERATORS:
            key = CaseKey(contract.source, contract.contract_id, item.format.value, spec.name)
            candidate = spec.fn(
                contract.paragraphs,
                item.edit,
                contract.language,
                operator_rng(seed, contract.contract_id, spec.name),
            )
            if isinstance(candidate, NotApplicable):
                not_applicable.append((key, candidate.reason))
                continue
            case_dir = item.baseline_path.parent.name
            case_workdir = workdir / "cases" / case_dir / spec.name
            jobs.append(CaseJob(key, spec.expectation, item, candidate, case_workdir))
    outcomes = _map_isolated(case_fn or execute_case, jobs, workers=workers, timeout=case_timeout)
    results = [
        outcome if isinstance(outcome, CaseResult) else _error_result(job, outcome, case_timeout)
        for job, outcome in zip(jobs, outcomes, strict=True)
    ]
    return RunResult(
        results=sorted(results, key=lambda result: result.key),
        draft_failures=sorted(draft_failures, key=lambda f: (f.source, f.contract_id, f.format)),
        not_applicable=sorted(not_applicable),
        pdf_replacements=sum(p.pdf_replacements for p in prepared if p.format is Format.PDF),
    )


# Spawned workers get independent hash seeds, so a policy sealed in one worker is
# verified in another - the same cross-process path a CLI user takes.
START_METHOD = "spawn"


class _Timeout:
    """Marker for an item whose worker did not answer in time."""


_Outcome = TypeVar("_Outcome")
_Item = TypeVar("_Item")


def _new_pool(workers: int) -> multiprocessing.pool.Pool:
    return multiprocessing.get_context(START_METHOD).Pool(max(1, workers))


def _map_isolated(
    function: Callable[[_Item], _Outcome],
    items: Sequence[_Item],
    *,
    workers: int,
    timeout: float,
) -> list[_Outcome | BaseException | _Timeout]:
    """Apply ``function`` in worker processes; a hung item never starves the others.

    When an item times out, finished results are kept, the pool (and with it the hung
    worker) is terminated, and every unfinished item is resubmitted to a fresh pool.
    Each round settles at least the timed-out item, so the loop always terminates.
    """
    outcomes: dict[int, _Outcome | BaseException | _Timeout] = {}
    remaining = list(range(len(items)))
    while remaining:
        pool = _new_pool(workers)
        try:
            handles = [(index, pool.apply_async(function, (items[index],))) for index in remaining]
            remaining = []
            for position, (index, handle) in enumerate(handles):
                try:
                    outcomes[index] = handle.get(timeout=timeout)
                except multiprocessing.TimeoutError:
                    outcomes[index] = _Timeout()
                    for other, other_handle in handles[position + 1 :]:
                        if other_handle.ready():
                            try:
                                outcomes[other] = other_handle.get(timeout=0)
                            except Exception as error:  # noqa: BLE001 - recorded
                                outcomes[other] = error
                        else:
                            remaining.append(other)
                    break
                except Exception as error:  # noqa: BLE001 - recorded, never a pass
                    outcomes[index] = error
        finally:
            pool.terminate()
            pool.join()
    return [outcomes[index] for index in range(len(items))]


def _failure_text(outcome: BaseException | _Timeout, timeout: float) -> str:
    if isinstance(outcome, _Timeout):
        return f"timeout after {timeout:g}s"
    return f"{type(outcome).__name__}: {outcome}"[:300]


def _prepare_all(
    contracts: Sequence[SourceContract],
    formats: Sequence[Format],
    workers: int,
    timeout: float,
    workdir: Path,
) -> tuple[list[PreparedContract], list[DraftFailure]]:
    tasks = [
        (contract, fmt, prepared_dir(workdir / "prepared", contract, fmt))
        for contract in contracts
        for fmt in formats
    ]
    outcomes = _map_isolated(_prepare_task, tasks, workers=workers, timeout=timeout)
    prepared: list[PreparedContract] = []
    failures: list[DraftFailure] = []
    for (contract, fmt, _), outcome in zip(tasks, outcomes, strict=True):
        if isinstance(outcome, PreparedContract):
            prepared.append(outcome)
        elif isinstance(outcome, DraftFailure):
            failures.append(outcome)
        else:
            failures.append(
                DraftFailure(
                    contract.source,
                    contract.contract_id,
                    fmt.value,
                    _failure_text(outcome, timeout),
                )
            )
    return prepared, failures


def _prepare_task(
    task: tuple[SourceContract, Format, Path],
) -> PreparedContract | DraftFailure:
    return prepare(*task)


def _error_result(job: CaseJob, outcome: BaseException | _Timeout, timeout: float) -> CaseResult:
    return CaseResult(
        key=job.key,
        expectation=job.expectation,
        text_verdict=None,
        raw_outcome=None,
        nonpass_rule_ids=(),
        edited_clause_chars=job.prepared.edited_clause_chars,
        baseline_clause_count=job.prepared.baseline_clause_count,
        duration_s=timeout,
        error=_failure_text(outcome, timeout),
    )
