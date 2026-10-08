# Evaluation Harness Design

Date: 2026-10-08
Status: draft for review

## Goal

Produce public, reproducible numbers for how well ArtifactDiff separates authorized
contract edits from unauthorized ones:

- **False-pass rate**: an unauthorized change gets a passing verdict. This is the
  headline safety number.
- **False-block rate**: an authorized-only edit is blocked, broken down by the rule
  that blocked it.
- **Draftability rate**: how many contracts yield a valid exact-replace policy at all.

The numbers must come from one command anyone can rerun, and they must be cut by
mutation type and file format. They feed the README and a write-up. The project goals
are open-source visibility and a portfolio/research artifact.

## Decisions already made

- **Data**: a hybrid of two sources.
  - A small synthetic corpus is committed (CC0) and runs in CI as a zero-false-pass
    gate.
  - CUAD v1 is downloaded on demand for the benchmark and never committed.
    - Source: Zenodo record 4595826, `CUAD_v1.zip`, CC BY 4.0.
    - SHA-256: `88b694d99007d39777fa44cd72daf8297773d285dc3eab0091ba32078888d18e`.
- **Formats**: DOCX and text-layer PDF, both rendered from the same paragraph list.
  Cross-format comparison (DOCX baseline vs. rendered PDF) is out of scope.
- **Visual evidence is disabled** in v1 (`VerificationOptions(visual=False)`), and the
  report says so. See "Acceptance and false-pass definitions" for how the resulting
  `contract-safe.visual.unavailable` finding is treated.
- **v1 measures and does not fix.** Known product issues (below) are reported, not
  patched, in this work. Fixes land in separate PRs, and before/after numbers are part
  of the write-up.

## Known issues the harness must surface

A feasibility probe was run on CUAD before this design. It used a throwaway script
that is not committed.

1. **Coarse clause segmentation.** For CUAD plain text rendered as DOCX paragraphs,
   13 of 20 sampled contracts produced only 1–2 clauses. Often the whole agreement was
   one unlabeled clause.
2. **The alignment budget blocks authorized edits in large clauses.**
   - `prove_atomic_occurrence_alignment` needs (len(before)+1)·(len(after)+1) cells.
   - `MAX_OCCURRENCE_ALIGNMENT_CELLS` is 4,000,000, which is exceeded once a clause
     reaches about 2,000 characters.
   - The expected rule then fails closed, so an authorized `180 days → 195 days` edit
     returned `FAIL` (`contract-safe.expected.r1`, `contract-safe.unexplained-clause`,
     `contract-safe.protected.durations`).
3. **Cost.** With visual evidence on, DOCX verification renders through LibreOffice
   and took 30–230 s per case.

The report attributes every false block to its blocking rule IDs, and records the
clause-size statistics of the edited clause. Issues 1 and 2 must therefore be visible
in the output without extra digging.

## Layout

```
evaluation/
  README.md                 # how to run, CUAD attribution, metric definitions
  __init__.py
  __main__.py               # CLI: `python -m evaluation ...`
  sources.py                # synthetic seeds + CUAD fetch/verify/extract
  render.py                 # paragraphs -> deterministic DOCX / PDF
  targets.py                # pick the authorized edit and build the selector/policy
  mutations.py              # mutation operators
  runner.py                 # case execution, isolation, parallelism
  report.py                 # metrics, JSON + Markdown report
  corpus/synthetic/*.yaml   # committed synthetic seed contracts (en + zh)
  data/raw/                 # gitignored: CUAD_v1.zip
  data/generated/           # gitignored: extracted text
tests/evaluation/           # unit tests + the CI synthetic gate
```

`evaluation/` is not part of the wheel. It imports `artifactdiff` only through
`ArtifactDiffApplication` and the public models, the same way a user would.

## Data flow

```
source contract (paragraph list)
  -> targets: choose an edit target, render the baseline, draft + seal the policy
     (once per contract x format; failures recorded as "not draftable" with reason)
  -> mutations: for each operator, derive a candidate paragraph list (or "n/a")
  -> render candidate in the same format
  -> verify_change(baseline, candidate, sealed policy, visual=False)
  -> case result row -> report
```

### Sources

- **Synthetic.** Each YAML seed is one contract written as clause-structured
  paragraphs. English uses headings like "Article II Payment Terms"; Chinese uses
  "第二条 付款条件".
  - There are 4 seeds in total: 2 English and 2 Chinese.
  - Each seed declares its authorized edit (clause selector, before, after) explicitly.
    The synthetic suite therefore does not depend on target auto-selection.
- **CUAD.**
  - `python -m evaluation fetch-cuad` downloads the archive into `data/raw/`,
    verifies the SHA-256, and extracts only `full_contract_txt/*.txt` into
    `data/generated/cuad/`.
  - Paragraphs are the text split on blank lines, with whitespace collapsed and empty
    paragraphs dropped.
  - Contracts are sampled by sorting file names, then shuffling with `--seed`, then
    taking `--limit`.

### Rendering

- **DOCX.** Use `python-docx`, one paragraph per entry, and rewrite the ZIP with fixed
  entry timestamps and ordering. Reuse the approach from `tests/factories.py` so the
  same input gives the same bytes.
- **PDF.** Use ReportLab with `invariant=1`, a fixed page size and margins, word
  wrapping, and page breaks.
  - English uses Helvetica. CUAD characters outside Latin-1 are replaced
    deterministically, identically in baseline and candidate, and the count of
    replacements is recorded.
  - Chinese uses ReportLab's built-in CID font `STSong-Light`, which is not embedded
    and covers GB characters. The bundled test subset font has only 90 CJK glyphs,
    which is too few for the mutation operators. A probe confirmed the PDF adapter
    extracts `STSong-Light` text with clauses, dates, durations, money and
    percentages intact.

### Authorized edit selection (`targets.py`)

Synthetic seeds declare their edit. For CUAD the edit is chosen automatically and
deterministically:

1. Parse the rendered baseline with the public inspect path.
2. Scan clauses in document order for a target value. Candidates are a duration
   (`N days|months|years`), a percentage, or a money amount. The value must occur
   exactly once in the whole document, so the edit is unambiguous.
3. The new value is the original plus a fixed offset (days +15, percentage +1, money
   +1000). The new value must not already occur in the document.
4. Build the selector:
   - `clause_label` = the clause's `label.normalized`;
   - `heading` = the clause heading;
   - `anchor` = the up to six words before the target inside the clause. If fewer
     than three words precede it, use the words after it. The anchor must be unique
     in the clause.
5. Call `draft_policy`, then `seal_policy` with no signer. If either raises, record
   the contract as not draftable with the exception type and message, and generate
   no cases for it.

### Mutation operators (`mutations.py`)

Each operator is a pure function. Its inputs are the paragraph list, the authorized
edit, and an RNG seeded from `(seed, contract_id, operator)`. It returns the candidate
paragraph list, or `NotApplicable(reason)`. Every operator except `authorized`,
`missing_edit` and `wrong_value` first applies the authorized edit and then makes its
own change. This models an agent that did the requested edit plus something else.

| Operator | Group | Change | Expectation |
|---|---|---|---|
| `authorized` | baseline | only the authorized edit | ACCEPT |
| `missing_edit` | application | candidate identical to baseline | BLOCK |
| `wrong_value` | application | authorized target set to a different value (+1 beyond the declared one) | BLOCK |
| `unit_change` | application | authorized number right, unit changed (`days` → `business days` / `天` → `个工作日`) | BLOCK |
| `same_para_number` | same paragraph | another number in the edited paragraph +1 | BLOCK |
| `same_para_negation` | same paragraph | insert negation after the first modal in the edited paragraph | BLOCK |
| `same_para_sentence_delete` | same paragraph | delete another sentence of the edited paragraph | BLOCK |
| `money_change` | elsewhere | another money amount +1 | BLOCK |
| `date_change` | elsewhere | another date +1 day (format preserved) | BLOCK |
| `duration_change` | elsewhere | another duration +1 | BLOCK |
| `percentage_change` | elsewhere | another percentage +1 | BLOCK |
| `party_change` | elsewhere | first company name (`… Inc.|LLC|Ltd.|Corporation`, or `甲方/乙方：…`) gets a word appended | BLOCK |
| `negation_insert` | elsewhere | `shall` → `shall not` (`应` → `不应`) | BLOCK |
| `negation_remove` | elsewhere | `shall not` → `shall` (`不得` → `可以`) | BLOCK |
| `modal_swap` | elsewhere | `may` → `shall` (`可以` → `应当`) | BLOCK |
| `sentence_insert` | elsewhere | insert a fixed obligation sentence into another paragraph | BLOCK |
| `sentence_delete` | elsewhere | delete one sentence of another paragraph | BLOCK |
| `paragraph_delete` | elsewhere | delete another whole paragraph | BLOCK |

"Elsewhere" means any paragraph other than the edited one. The site is chosen by the
seeded RNG among the applicable paragraphs. Language-specific tokens live in one
table per language. Operators that find no site return `NotApplicable`. These are
counted in the report's applicability table and excluded from rates.

### Acceptance and false-pass definitions

With visual evidence off, every run carries a `contract-safe.visual.unavailable`
REVIEW. The harness therefore computes a **text verdict**:

- the raw outcome after removing findings whose rule ID is
  `contract-safe.visual.unavailable`;
- PASS if no remaining finding is FAIL or REVIEW, otherwise the worst remaining
  outcome.

The case metrics are defined on the text verdict:

- An **ACCEPT** case is accepted iff its text verdict is PASS. Otherwise it is a
  false block, and the remaining non-pass rule IDs are recorded.
- A **BLOCK** case is a **false pass** iff its text verdict is PASS. FAIL and REVIEW
  both count as blocked, and the report shows the split.
- A runner error or timeout is reported separately. It never counts as pass or as
  accepted.

This treats the missing visual layer as passing. For false-pass counting that is the
conservative direction: it can only add passes, never hide one.

### Runner (`runner.py`)

- One `Case` is `(source, contract_id, format, operator)`.
- Policy drafting and sealing happen once per `(contract, format)`. Each case then
  gets its own temporary input/output roots, so no bundle or session is reused.
- Cases run in a `multiprocessing` pool (`--workers`, default CPU count). Each case
  has a timeout (`--case-timeout`, default 120 s).
- Each result row has these fields: case key; expectation; text verdict; raw outcome;
  non-pass rule IDs; edited-clause character length; clause count of the baseline;
  duration; error.
- Rows are written to `results.jsonl`, sorted by case key. Two runs with the same
  inputs and seed produce identical files except for durations.

### Report (`report.py`)

The report has two outputs:

- `summary.json` with these fields: run metadata (source, CUAD SHA-256, ArtifactDiff
  version and git commit, seed, limit, formats, options); counts; and the metrics
  below.
- `report.md`, a readable version of the same data. It contains no contract text,
  only IDs and numbers. It includes the CUAD CC BY 4.0 attribution when CUAD is used.

Metrics, each overall and by format and by operator/group:

- false-pass count and rate, with a Wilson 95% interval;
- FAIL / REVIEW split for blocked cases;
- acceptance rate for `authorized`, and false-block reasons ranked by rule ID;
- false blocks bucketed by edited-clause length (`<1k`, `1–2k`, `2–5k`, `>5k`
  characters), which makes the alignment-budget issue explicit;
- draftability rate, with not-draftable reasons ranked;
- operator applicability counts;
- median and p95 case duration.

### CLI

```
python -m evaluation fetch-cuad
python -m evaluation run --source synthetic|cuad [--formats docx,pdf] [--limit N]
                         [--seed 0] [--workers K] [--case-timeout 120]
                         --output build/eval/<name>
```

The `--output` directory must be empty or absent, which matches the Golden Path
script's convention.

## CI gate

`tests/evaluation/test_synthetic_gate.py` runs the synthetic source for both formats
through the same runner and asserts:

- zero false passes;
- every `authorized` case is accepted;
- every operator is applicable to at least one seed, so no operator silently
  disappears;
- no runner errors.

This runs inside the existing `pytest` step. Its budget is under 60 s on a CI runner.
CUAD is never fetched in CI.

`pyproject.toml` gets `pythonpath = ["."]` under `[tool.pytest.ini_options]` so tests
can import `evaluation`. `mypy` and `ruff` cover `evaluation/` in CI too.

## Error handling

- CUAD fetch failure or checksum mismatch: exit nonzero with a clear message, and
  leave no partially extracted data.
- A character the Chinese CID font cannot encode: ReportLab raises, and the case
  becomes a recorded error. It is never silently dropped.
- A per-case exception or timeout: recorded in the row's `error`, and the run
  continues. The summary makes errors prominent, and the CI gate fails on any error.

## Testing

- **Operators**: one unit test per operator on a small fixed paragraph list. Each
  asserts the exact textual change, determinism under the same seed, and
  `NotApplicable` when there is no site.
- **Rendering**: rendering the same paragraphs twice gives identical bytes for DOCX
  and PDF. The PDF text layer round-trips through the PDF adapter.
- **Target selection**: uniqueness rules, anchor fallback, and not-draftable
  recording, on small handcrafted documents.
- **Metrics**: the text-verdict reduction, the Wilson interval against known values,
  and the bucketing.
- **End to end**: the synthetic gate above.

## Out of scope for v1

- Fixing clause segmentation or the alignment budget.
- Visual-evidence evaluation, cross-format DOCX↔PDF, OCR/scanned PDFs.
- Chinese real-contract data (none with a suitable license was found).
- Signed policies and bundles in the benchmark. Policies are sealed without a signer,
  because signing does not affect the verdict logic under test.
- Publishing CUAD-derived files.
