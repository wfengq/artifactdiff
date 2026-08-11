# ArtifactDiff Exact-Occurrence Alignment Correction Design

Date: 2026-08-11
Status: approved design; written-spec review pending
Parent design: `2026-08-04-artifactdiff-contract-verification-gate-design.md`
Parent plan: `../plans/2026-08-04-contract-policy-verdict.md`

## 1. Purpose

Close the remaining Plan 2 authorization gap: an expected exact replacement must not be credited when the declared `after` text appears at a different, merely similar occurrence in the candidate clause.

This correction preserves the approved behavior that a proven expected replacement may coexist with other edits covered by an explicit `allow` rule. It does not change policy schema 1.0, selectors, visual verification, review approvals, or evidence privacy.

## 2. Safety Invariant

For every declared exact replacement, ArtifactDiff must prove that each baseline `before` span corresponds to exactly one candidate `after` span in the same resolved clause.

- A unique, required correspondence yields expected `PASS`.
- A missing mapping, a different mapping, multiple equally valid mappings, overlapping/crossing mappings, or exhausted alignment budget yields a nonapprovable expected `FAIL`.
- Other edits are evaluated separately by the existing allow phase and may yield approvable `REVIEW`; they cannot repair or override an expected `FAIL`.

## 3. Chosen Approach: Bounded Atomic-Anchor Global Alignment

The evaluator will replace the current whole-clause distance-improvement heuristic with a bounded dynamic-programming alignment over the baseline and candidate clause text.

Each declared replacement occurrence contributes an atomic authorization edge from its baseline span to a candidate span containing the declared `after` value. Taking that edge represents exactly the declared operation and has zero residual-edit cost. Ordinary insertions, deletions, and substitutions retain unit cost.

The alignment result is acceptable only when:

1. all declared occurrence anchors can be used in monotonic, non-overlapping order;
2. the minimum authorized alignment uses every required anchor;
3. omitting or remapping any required anchor cannot achieve the same minimum cost; and
4. the verdict-wide cell budget is not exceeded.

This tests occurrence identity rather than whether replacing some candidate `after` text happens to reduce a global scalar distance.

## 4. Components and Data Flow

### 4.1 Span discovery

The existing NFC-normalized exact span discovery remains authoritative. Occurrence counts must still match the frozen policy before alignment begins.

### 4.2 Alignment request

For a resolved clause pair, the expected phase supplies:

- normalized baseline and candidate text;
- ordered baseline `before` spans;
- ordered candidate `after` spans;
- a shared verdict-wide alignment budget.

The helper returns a closed result: `proven` or `not_proven`. It does not return a best-effort confidence score.

### 4.3 Atomic-anchor proof

The implementation computes the minimum residual edit cost for an order-preserving mapping that consumes every declared anchor. It also computes the best competing cost when a required anchor is absent or mapped differently. The mapping is proven only when the all-anchor result is strictly better than every competitor.

Only occurrence mapping must be unique. Ordinary character-level edit paths may remain non-unique when they imply the same required span mapping.

### 4.4 Verdict integration

`_expected_phase` sets `applied=True` only when counts match and alignment returns `proven`. An unproven mapping emits the existing `contract-safe.expected.<id>` nonapprovable `FAIL`. The allow phase continues to classify residual edits only after expected-operation authorization has been established.

## 5. Resource and Failure Boundaries

- Retain `MAX_OCCURRENCE_ALIGNMENT_CELLS` as one total budget per verdict, not per rule.
- Debit the budget before allocating or filling a DP region.
- Reject overlapping anchors and candidate-order inversions.
- Treat malformed input, ambiguity, and budget exhaustion identically for authorization: fail closed.
- Do not add network, model, probabilistic matching, or parser dependencies.

## 6. Required Tests

TDD starts with the independent review counterexample:

```text
baseline:  First required position: RED\nSecond unrelated position: RDX
candidate: First required position: GREEN\nSecond unrelated position: BLUE
expected:  RED -> BLUE
allow:     modified
```

The expected finding must be nonapprovable `FAIL`, and the verdict must remain `FAIL` even though the unrelated edits are allowed.

Regression coverage must also include:

- correct exact replacement plus an allowed extra edit remains approvable `REVIEW`;
- the existing repeated-context `RED/YELLOW` adversarial case;
- multiple independent expected operations in one clause;
- multiple occurrences of one exact operation in stable order;
- ambiguous equal-cost occurrence mapping fails closed;
- crossing/reordered mapping fails closed;
- multilingual text remains deterministic;
- verdict-wide budget exhaustion fails closed;
- canonical verdict bytes remain input-order deterministic.

## 7. Verification Gate

Before Plan 2 may be marked complete:

1. record the new adversarial test failing for the expected reason;
2. make the focused occurrence tests pass with the minimal implementation;
3. run the complete verification-related suite;
4. run the full test suite, Ruff, format check, mypy, and `git diff --check`;
5. perform one scoped read-only review of the correction diff;
6. require zero open Critical or Important findings.

## 8. Explicit Non-Goals

- No policy schema or frozen-bundle migration.
- No agent-supplied provenance or tracked-revision dependency.
- No fuzzy semantic equivalence for expected replacements.
- No Plan 3 work.
- No unrelated refactor of the verification rules module.
