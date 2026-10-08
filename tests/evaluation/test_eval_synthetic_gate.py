"""CI gate: the committed synthetic corpus must never produce a false pass."""

import os
import time
from pathlib import Path

from evaluation.models import Expectation, Format
from evaluation.mutations import OPERATORS
from evaluation.runner import run_cases
from evaluation.sources import load_synthetic


def test_synthetic_gate(tmp_path: Path) -> None:
    started = time.monotonic()
    run = run_cases(
        load_synthetic(),
        [Format.DOCX, Format.PDF],
        seed=0,
        workers=os.cpu_count() or 2,
        case_timeout=60,
        workdir=tmp_path,
    )
    elapsed = time.monotonic() - started

    assert run.draft_failures == []
    assert [r.key for r in run.results if r.error is not None] == []
    assert [r.key for r in run.results if r.false_pass] == []
    authorized = [r for r in run.results if r.key.operator == "authorized"]
    assert len(authorized) == 8
    must_accept = [r for r in run.results if r.expectation is Expectation.ACCEPT]
    assert [r.key for r in must_accept if not r.accepted] == []
    assert {r.key.operator for r in run.results} == {spec.name for spec in OPERATORS}
    assert elapsed < 60
