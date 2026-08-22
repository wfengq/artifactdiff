# Plan 4.5: Contract Golden Path Acceptance

Status: accepted.

## Scope

Plan 4.5 validates the approved product promise without adding a new verification
architecture: a trusted policy authorizer specifies one exact contract edit before an
agent works; ArtifactDiff then proves whether the candidate contains only that edit and
records the result in an immutable Review Bundle.

The bounded acceptance matrix is:

1. exact authorized payment-window edit: `PASS`;
2. authorized edit plus an unexplained non-protected visual change: blocking `REVIEW`,
   resolvable only by a signed, finding-bound human approval;
3. authorized edit plus a protected party change: nonapprovable `FAIL`.

## Required gates

- All cases use a signed frozen policy and controlled edit session.
- All bundles report `verified` assurance and valid creation signatures.
- Review is blocking unless an explicit approval event is appended.
- A FAIL finding cannot be approved.
- Every bundle verifies independently after creation and after any approval event.
- Demo artifacts contain synthetic data and no persisted private-key material.
- The focused acceptance test and complete repository suite pass.

## Deliverables

- `scripts/run_contract_golden_path.py`
- `examples/contract-golden-path/README.md`
- `tests/acceptance/test_contract_golden_path.py`
- generated `summary.json` and Review Bundles when the runner is invoked

## Acceptance result

- Golden Path focused tests: `2 passed`.
- Directory publication and affected workflow regression: `101 passed`.
- Complete repository regression: `910 passed`.
- Ruff and strict mypy on all changed Python files: passed.
- Synthetic approved run: authorized `PASS`, visual exception `REVIEW` then signed
  effective `PASS`, unauthorized party edit nonapprovable `FAIL`; every Review Bundle
  verified with valid creation signature, current trust, and event chain.
