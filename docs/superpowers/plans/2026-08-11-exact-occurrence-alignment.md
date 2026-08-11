# Exact-Occurrence Alignment Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make exact expected replacements pass only when a bounded global alignment proves a unique baseline-span to candidate-span correspondence.

**Architecture:** Add a focused alignment module that runs deterministic Levenshtein dynamic programming with zero-cost atomic authorization edges. Track the intersection of anchors used by all minimum-cost paths; authorization succeeds only when every optimal path uses every required anchor. Wire the closed boolean result into the existing expected phase while keeping residual edits, allow rules, policy schema, and visual behavior unchanged.

**Tech Stack:** Python 3.11-3.13, standard-library dataclasses and dynamic programming, existing Pydantic Contract IR, pytest, Ruff, mypy.

## Global Constraints

- Preserve policy schema `1.0`; do not add frozen-policy fields or migrations.
- Preserve the approved `PASS` / approvable `REVIEW` / nonapprovable `FAIL` contract.
- Treat missing, wrong, ambiguous, crossing, or budget-exhausted occurrence mappings as nonapprovable `FAIL`.
- Keep `MAX_OCCURRENCE_ALIGNMENT_CELLS = 4_000_000` as one total budget per verdict.
- Do not add network, model, probabilistic matching, parser dependencies, or Plan 3 work.
- Modify only the alignment helper, expected-phase integration, occurrence tests, and SDD audit records.

---

## File Map

- Create `src/artifactdiff/verification/alignment.py`: bounded atomic-anchor alignment types, validation, DP, and fail-closed proof function.
- Modify `src/artifactdiff/verification/rules.py`: remove the whole-clause distance-improvement heuristic and call the alignment module from `_expected_phase`.
- Create `tests/unit/verification/test_alignment.py`: direct resource-boundary and mapping-proof tests.
- Modify `tests/unit/verification/test_rules.py`: public evaluator regressions for the independent-review counterexample and approved exact-plus-allow behavior.
- Update `.superpowers/sdd/2026-08-04-contract-policy-verdict/progress.md`: ignored audit ledger only; never stage it in the product commit.

### Task 1: Lock the Public Fail-Closed Behavior with RED Tests

**Files:**
- Modify: `tests/unit/verification/test_rules.py:394-477`
- Create: `tests/unit/verification/test_alignment.py`

**Interfaces:**
- Consumes: existing `_contract`, `_clause`, `_frozen`, `_evaluate`, `FindingOutcome` test helpers.
- Produces: failing public behavior tests and the wished-for alignment interface used by Task 2.

- [ ] **Step 1: Add the independent-review near-collision regression**

Add beside the existing wrong-repeated-context test:

```python
def test_near_collision_cannot_credit_expected_operation_at_wrong_occurrence() -> None:
    baseline = _contract(
        _clause(
            "before-payment",
            "Payment obligations\nFirst required position: RED\nSecond unrelated position: RDX",
        ),
        sha="a",
    )
    candidate = _contract(
        _clause(
            "after-payment",
            "Payment obligations\nFirst required position: GREEN\nSecond unrelated position: BLUE",
        ),
        sha="b",
    )

    verdict = _evaluate(
        baseline,
        candidate,
        _frozen(baseline, before="RED", after="BLUE", allow=True),
    )

    expected = next(
        item
        for item in verdict.findings
        if item.rule_id == "contract-safe.expected.payment-window"
    )
    assert verdict.outcome is FindingOutcome.FAIL
    assert expected.outcome is FindingOutcome.FAIL
    assert expected.approvable is False
```

- [ ] **Step 2: Run the new test and record strict RED**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification/test_rules.py::test_near_collision_cannot_credit_expected_operation_at_wrong_occurrence -q
```

Expected: one assertion failure showing the current verdict is `review` and the expected finding is `pass`. A collection/import error is not an acceptable RED.

- [ ] **Step 3: Add direct wished-for alignment tests**

Create `tests/unit/verification/test_alignment.py` with these concrete cases:

```python
from artifactdiff.verification.alignment import (
    AlignmentBudget,
    OccurrenceAnchor,
    TextSpan,
    prove_atomic_occurrence_alignment,
)


def _span(text: str, value: str) -> TextSpan:
    start = text.index(value)
    return TextSpan(start=start, end=start + len(value))


def test_correct_anchor_is_required_by_every_optimal_path() -> None:
    before = "Payment: RED; fee unchanged."
    after = "Payment: BLUE; fee revised."
    assert prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "RED"), _span(after, "BLUE")),),
        AlignmentBudget(),
    )


def test_distant_near_collision_is_not_a_proven_anchor() -> None:
    before = "First: RED\nSecond: RDX"
    after = "First: GREEN\nSecond: BLUE"
    assert not prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "RED"), _span(after, "BLUE")),),
        AlignmentBudget(),
    )


def test_budget_exhaustion_fails_closed_without_overspending() -> None:
    budget = AlignmentBudget(remaining_cells=8)
    before = "A RED B"
    after = "A BLUE B"
    assert not prove_atomic_occurrence_alignment(
        before,
        after,
        (OccurrenceAnchor(_span(before, "RED"), _span(after, "BLUE")),),
        budget,
    )
    assert budget.remaining_cells == 8
```

- [ ] **Step 4: Run the direct tests and verify the expected import RED**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification/test_alignment.py -q
```

Expected: collection error only because `artifactdiff.verification.alignment` does not exist. This RED is acceptable after the public behavior RED has already proved the production defect.

### Task 2: Implement the Bounded Atomic-Anchor Aligner

**Files:**
- Create: `src/artifactdiff/verification/alignment.py`

**Interfaces:**
- Consumes: NFC-normalized strings and exact half-open spans discovered by the evaluator.
- Produces:
  - `TextSpan(start: int, end: int)`
  - `OccurrenceAnchor(before: TextSpan, after: TextSpan)`
  - `AlignmentBudget(remaining_cells: int = 4_000_000)`
  - `prove_atomic_occurrence_alignment(before_text: str, after_text: str, anchors: tuple[OccurrenceAnchor, ...], budget: AlignmentBudget) -> bool`

- [ ] **Step 1: Define immutable spans/anchors and the shared mutable budget**

Implement:

```python
from dataclasses import dataclass

MAX_OCCURRENCE_ALIGNMENT_CELLS = 4_000_000


@dataclass(frozen=True, slots=True)
class TextSpan:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class OccurrenceAnchor:
    before: TextSpan
    after: TextSpan


@dataclass(slots=True)
class AlignmentBudget:
    remaining_cells: int = MAX_OCCURRENCE_ALIGNMENT_CELLS
```

Reject empty/out-of-range spans, overlaps, and non-monotonic start/end coordinates by returning `False`, never by raising through the verdict boundary.

- [ ] **Step 2: Implement one bounded DP with atomic jump edges**

Use a row-major Levenshtein grid. Each cell stores:

```python
@dataclass(frozen=True, slots=True)
class _State:
    cost: int
    required_by_all: int
```

Merge transitions as follows:

```python
def _merge(current: _State | None, candidate: _State) -> _State:
    if current is None or candidate.cost < current.cost:
        return candidate
    if candidate.cost == current.cost:
        return _State(current.cost, current.required_by_all & candidate.required_by_all)
    return current
```

Ordinary insertion/deletion/substitution transitions preserve the mask and cost `1`, `1`, or `0/1`. At the exact source coordinate of anchor `i`, schedule a jump to its exact destination coordinate with unchanged cost and `required_by_all | (1 << i)`. Pending jump states may be stored by destination row/column so only the previous and current ordinary DP rows are retained.

Before allocating/filling the grid, compute `cells = (len(before_text) + 1) * (len(after_text) + 1)`. If `cells > budget.remaining_cells`, return `False` without changing the budget. Otherwise debit exactly `cells` once.

Return `True` only when the terminal state's `required_by_all` equals `(1 << len(anchors)) - 1`. This proves every minimum-cost path uses every declared atomic replacement while allowing non-unique ordinary character paths that imply the same span mapping.

- [ ] **Step 3: Run direct alignment tests to GREEN**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification/test_alignment.py -q
```

Expected: `3 passed`.

- [ ] **Step 4: Add validation matrix tests before refactoring**

Add parameterized tests proving fail-closed behavior for an empty span, out-of-range span, overlapping anchors, and reversed candidate order. Add a positive test with two ordered anchors and a Unicode/NFC test. Run the new cases before any extra implementation; any missing behavior must fail first, then make the smallest validation change to pass.

- [ ] **Step 5: Run the complete alignment module tests**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification/test_alignment.py -q
```

Expected: all tests pass with no warnings.

### Task 3: Replace the Heuristic at the Expected-Phase Boundary

**Files:**
- Modify: `src/artifactdiff/verification/rules.py:65-78,331-404,453-521`
- Modify: `tests/unit/verification/test_rules.py:394-477,1311-1353`

**Interfaces:**
- Consumes: the Task 2 alignment types and proof function.
- Produces: existing `RawVerdict` and `Finding` interfaces with corrected expected-operation authorization.

- [ ] **Step 1: Wire exact spans into atomic anchors**

Import `AlignmentBudget`, `OccurrenceAnchor`, `TextSpan`, and `prove_atomic_occurrence_alignment`. Remove local `_Span`, `_AlignmentBudget`, `_bounded_edit_distance`, `_revert_occurrences`, and the old `_occurrences_correspond` implementation.

Keep `_find_spans`, returning `tuple[TextSpan, ...]`. Build ordinal anchors only after the existing exact occurrence counts pass:

```python
anchors = tuple(
    OccurrenceAnchor(before=before_span, after=after_span)
    for before_span, after_span in zip(before_spans, after_spans, strict=True)
)
corresponds = counted and prove_atomic_occurrence_alignment(
    before_text,
    after_text,
    anchors,
    alignment_budget,
)
```

Set `applied = counted and corresponds`. Do not let an unproven correspondence produce an expected `PASS`. Preserve `exact` as comparison of the mechanically reconstructed clause with the candidate clause.

- [ ] **Step 2: Run the independent-review regression to GREEN**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification/test_rules.py::test_near_collision_cannot_credit_expected_operation_at_wrong_occurrence -q
```

Expected: `1 passed`.

- [ ] **Step 3: Run the existing contract-safe occurrence regressions**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification/test_rules.py -k "occurrence or repeated_context or extra_edit_inside_explicit_allow or multiple_independent_expected or multilingual" -q
```

Expected: all selected tests pass. Specifically, exact-plus-allow remains `REVIEW`, wrong occurrence remains `FAIL`, multiple expected operations remain `PASS`, and budget exhaustion remains `FAIL`.

- [ ] **Step 4: Add the remaining behavior matrix with RED-before-GREEN discipline**

Add public evaluator tests for two occurrences of one operation, ambiguous equal-cost mapping, reversed/crossing occurrence order, and deterministic bilingual text. For each missing behavior, run the individual test first and record RED before changing production code. Make only alignment/integration changes needed to pass.

- [ ] **Step 5: Run the full verification unit suite**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification -q
```

Expected: all verification unit tests pass.

- [ ] **Step 6: Commit the correction**

Run:

```powershell
git add -- src/artifactdiff/verification/alignment.py src/artifactdiff/verification/rules.py tests/unit/verification/test_alignment.py tests/unit/verification/test_rules.py
git diff --cached --check
git commit -m "fix: bind exact replacements to occurrences"
```

Do not stage `.superpowers/` files.

### Task 4: Verify, Audit, and Gate Plan 2

**Files:**
- Update ignored ledger: `.superpowers/sdd/2026-08-04-contract-policy-verdict/progress.md`
- No production changes unless a newly added test first demonstrates a correction-scope defect.

**Interfaces:**
- Consumes: committed correction diff and the approved design checklist.
- Produces: fresh verification evidence and a zero-Critical/Important completion decision.

- [ ] **Step 1: Run related integration and legacy regressions**

Run:

```powershell
.venv\Scripts\python -m pytest tests/unit/verification tests/integration/verification tests/integration/test_service_orchestration.py tests/integration/test_service_weighting.py tests/integration/test_service_visual_degradation.py -q
```

Expected: all selected tests pass.

- [ ] **Step 2: Run the complete project suite**

Run:

```powershell
.venv\Scripts\python -m pytest -q
```

Expected: zero failures.

- [ ] **Step 3: Run static and diff checks**

Run:

```powershell
.venv\Scripts\python -m ruff check src tests
.venv\Scripts\python -m ruff format --check src tests
.venv\Scripts\python -m mypy src/artifactdiff/verification/alignment.py src/artifactdiff/verification/rules.py
git diff --check HEAD^..HEAD
git status --short
```

Expected: Ruff and mypy succeed, diff check succeeds, and the tracked worktree is clean.

- [ ] **Step 4: Update the ignored audit ledger**

Record the correction-cycle base/head, strict RED output, GREEN commands and counts, static checks, and the fact that no subagent wrote shared files. Do not stage the ledger.

- [ ] **Step 5: Perform one scoped read-only review**

Review the correction commit against `docs/superpowers/specs/2026-08-11-exact-occurrence-alignment-design.md`. Re-run the independent-review counterexample and inspect resource accounting, monotonic anchor validation, exact-plus-allow behavior, and public verdict semantics.

Plan 2 completes only with:

```text
Open Critical: 0
Open Important: 0
```

Any remaining Critical or Important finding keeps Plan 2 blocked and prevents Plan 3 from starting.
