# Task 4 Report: contract-safe verdict evaluation

## Root cause

The interrupted implementation had the rule engine and its broad test coverage in
place, but two contract-safe decisions were not encoded correctly.  The visual
branch treated every unpaired page as pagination reflow, which made a deleted
baseline page approvable under the default `pagination_reflow="review"` policy.
Also, `FindingEvidence.locations` was bounded by the model but the finding
constructors never populated it, so findings were not evidence-backed even when
the Contract IR contained semantic or rendered evidence.  Static checks also
identified two unsorted imports and an invariant `list[VisualPageChange]` passed
to a `list[object]` parameter.

## TDD RED/GREEN record

1. Added the semantic-evidence and page-deletion tests.
   - RED: `.venv\\Scripts\\python.exe -m pytest tests/unit/verification/test_rules.py::test_expected_operation_finding_links_semantic_evidence tests/unit/verification/test_rules.py::test_deleted_baseline_page_is_a_nonapprovable_fail tests/unit/verification/test_rules.py::test_deleted_baseline_page_fails_even_with_review_pagination_policy -q`
   - Result: `3 failed`; the expected finding had `locations == []`, while both
     deleted-page cases returned `FindingOutcome.REVIEW` from
     `contract-safe.visual.pagination-reflow`.
   - GREEN: reran the same command after adding deterministic evidence locations
     and the explicit page-deletion rule.
   - Result: `3 passed in 0.37s`.

2. Added feature-evidence assertions for every non-metadata feature kind.
   - RED: `.venv\\Scripts\\python.exe -m pytest tests/unit/verification/test_rules.py::test_feature_changes_review_approvably_without_exposing_content -q`
   - Result: `5 failed`; each finding had `evidence.locations == []`.
   - GREEN: reran the same command after attaching matched feature evidence.
   - Result: `5 passed in 0.37s`.

3. Added a protected-party evidence assertion.
   - RED: `.venv\\Scripts\\python.exe -m pytest tests/unit/verification/test_rules.py::test_party_change_outside_exact_authorized_span_fails -q`
   - Result: `1 failed`; the protected-entity finding had no locations.
   - GREEN: reran the same command after attaching matching entity evidence from
     both contract sides.
   - Result: `1 passed in 0.37s`.

## Changes

- `src/artifactdiff/verification/models.py`: strict, bounded finding/verdict
  models and canonical bytes.
- `src/artifactdiff/verification/rules.py`: deterministic integrity-first
  evaluator, exact-operation/span authorization, protected/feature/clause rules,
  evidence-backed findings, stable ordering, and a non-approvable baseline-page
  deletion branch.
- `src/artifactdiff/verification/visual_rules.py`: deterministic visual helpers,
  including explicit page deletion and evidence locations.
- `src/artifactdiff/verification/__init__.py`: public evaluator/verdict exports.
- `tests/unit/verification/test_rules.py` and `test_visual_rules.py`: coverage
  for strict models, stable IDs/bytes/order, expected edits, protected content,
  feature/metadata behavior, visual envelopes/reflow/deletion, unavailable
  visuals, malformed/oversized input, evidence links, and finding caps.

## Verification

- `.venv\\Scripts\\python.exe -m pytest tests/unit/verification/test_rules.py tests/unit/verification/test_visual_rules.py -q` — `47 passed in 0.41s`.
- `.venv\\Scripts\\python.exe -m pytest tests/unit/verification -q` — `83 passed in 0.49s`.
- `.venv\\Scripts\\python.exe -m pytest tests/unit/contract tests/integration/contract tests/unit/policy tests/integration/policy tests/unit/verification -q` — `413 passed in 8.25s`.
- `.venv\\Scripts\\python.exe -m pytest -q` — `527 passed in 11.79s`.
- `.venv\\Scripts\\ruff.exe check src/artifactdiff/verification tests/unit/verification` — clean.
- `.venv\\Scripts\\ruff.exe format --check src/artifactdiff/verification tests/unit/verification` — `8 files already formatted`.
- `.venv\\Scripts\\mypy.exe src/artifactdiff/contract src/artifactdiff/policy src/artifactdiff/verification` — `Success: no issues found in 20 source files`.
- `git diff --check` — clean.

## Self-review and remaining concerns

The evaluator remains entirely local and deterministic; it does not add file
loading, orchestration, CLI/MCP, signatures, approvals, bundles, or UI.  Evidence
records use `EvidenceRef` identifiers and geometry only; comment, hidden-text,
and link payloads are not copied into findings.  Page deletion is deliberately
not a policy relaxation: it always fails, while candidate page additions and
authorized-edit reflow continue to follow `pagination_reflow`.  No remaining
Task 4 concerns were identified.
