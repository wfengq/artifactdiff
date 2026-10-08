# ArtifactDiff evaluation harness

This harness measures how well ArtifactDiff separates an authorized contract edit from
unauthorized ones. It runs on two sources:

- **synthetic**: four committed seed contracts, two English and two Chinese (CC0). They
  run in CI as a zero-false-pass gate.
- **cuad**: the 510 English commercial contracts of
  [CUAD v1](https://zenodo.org/records/4595826). They are downloaded on demand and never
  committed.

Each contract is rendered to DOCX and to a text-layer PDF. The harness picks or reads
one authorized exact edit (for example `30 days → 45 days`), then drafts and seals a
`contract-safe` policy for it. It then verifies 18 candidates: the authorized edit
alone, plus 17 mutations that an agent should never get through.

## Run it

```console
# Synthetic corpus (seconds)
python -m evaluation run --source synthetic --output build/eval/synthetic

# CUAD (downloads ~106 MB once and verifies its SHA-256)
python -m evaluation fetch-cuad
python -m evaluation run --source cuad --limit 100 --output build/eval/cuad-100
```

`run` options:

| Option | Default | Meaning |
|---|---|---|
| `--formats` | `docx,pdf` | which formats to render |
| `--limit` | all | number of contracts, sampled with `--seed` |
| `--seed` | `0` | contract sampling and mutation-site choice |
| `--workers` | CPU count | parallel worker processes |
| `--case-timeout` | `120` | seconds per case before it is recorded as an error |

`fetch-cuad --archive PATH` reuses a `CUAD_v1.zip` you already downloaded.

`run` exits with status 1 when any case errored or timed out. Errors are excluded from
the false-pass denominator, so a run with errors must not be read as clean.

Each run writes three files to `--output`:

- `results.jsonl`: one row per case;
- `summary.json`: all metrics;
- `report.md`: the same metrics in readable form.

The report contains IDs and numbers only, never contract text.

## Mutations

Each operator has an expectation. `authorized` must be **accepted**; every other operator
must be **blocked**.

| Group | Operators |
|---|---|
| baseline | `authorized` |
| application | `missing_edit`, `wrong_value`, `unit_change` |
| same paragraph | `same_para_number`, `same_para_negation`, `same_para_sentence_delete` |
| elsewhere | `money_change`, `date_change`, `duration_change`, `percentage_change`, `party_change`, `negation_insert`, `negation_remove`, `modal_swap`, `sentence_insert`, `sentence_delete`, `paragraph_delete` |

Every operator except `authorized`, `missing_edit` and `wrong_value` first applies the
authorized edit and then makes its own change. This models an agent that did what was
asked plus something else.

The harness finds mutation sites with its own patterns, never with ArtifactDiff's entity
extractor. This keeps the benchmark from testing only values the tool already
recognizes. An operator with no site in a contract is reported as not applicable, and
it is excluded from rates.

## Metric definitions

Visual evidence is **disabled** (`visual=False`). Every run therefore carries a
`contract-safe.visual.unavailable` REVIEW finding, and metrics use a **text verdict**:
the outcome after dropping that one finding.

- **False pass**: a case that should be blocked gets a text verdict of `pass`. Failing
  that way can only overstate passes, never hide one. Rates come with Wilson 95%
  intervals.
- **False pass where the authorized edit passed**: the same rate, restricted to the
  contract×format pairs whose `authorized` case was accepted. When the gate blocks the
  authorized edit, it blocks every candidate of that pair wholesale, so those cases say
  nothing about telling edits apart. This conditional rate is the one that measures
  discrimination.
- **Accepted**: the `authorized` case gets a text verdict of `pass`. Any other
  verdict is a false block. Its remaining rule IDs are counted under "Why authorized
  edits were blocked", and also bucketed by the length of the edited clause.
- **Draftable**: the harness found a unique edit target and anchor, and ArtifactDiff
  accepted the policy. Failures are listed with their reason.
- **Runner errors and timeouts** are excluded from false-pass denominators, and count as
  not accepted for `authorized`. They are never counted as passes.

## Limitations

- Visual evidence is not evaluated. Cross-format DOCX↔PDF comparison and OCR are out
  of scope.
- CUAD is English only. No openly licensed Chinese real-contract corpus was found.
  Chinese coverage comes from the synthetic seeds.
- CUAD plain text has little structure. How ArtifactDiff segments it into clauses is
  part of what is being measured.

## Attribution

Contains material from the Contract Understanding Atticus Dataset (CUAD) v1 by The
Atticus Project, licensed under CC BY 4.0.
