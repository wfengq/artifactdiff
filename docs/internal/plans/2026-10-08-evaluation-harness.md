# Evaluation Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `python -m evaluation`. It measures ArtifactDiff's false-pass, false-block and draftability rates on a committed synthetic corpus (CI gate) and on CUAD v1 (on-demand benchmark), for DOCX and text-layer PDF.

**Architecture:**
- A source contract is a list of paragraphs.
- It is rendered deterministically to DOCX/PDF, and an exact-replace policy is drafted and sealed once per contract × format.
- Mutation operators derive candidate paragraph lists, and each candidate is verified with `visual=False`.
- Each case's findings are reduced to a "text verdict". Results go to `results.jsonl`, `summary.json` and `report.md`.

**Tech Stack:** Python ≥3.11, the existing `artifactdiff` package, python-docx, ReportLab (incl. the built-in `STSong-Light` CID font), PyYAML, stdlib `multiprocessing`/`urllib`/`zipfile`/`hashlib`, pytest.

**Spec:** `docs/internal/specs/2026-10-08-evaluation-harness-design.md`

## Global Constraints

- `evaluation/` is a top-level package outside the wheel. It uses only `ArtifactDiffApplication`, `ClauseSelector`, `TrustStore`, `VerificationOptions`, `FindingOutcome` and the inspect payload. It must **not** import `artifactdiff.contract.entities`: mutation sites come from the harness's own patterns, so the benchmark is not limited to values the extractor already recognizes.
- No new runtime or dev dependencies.
- The CUAD constants, verbatim:
  - URL: `https://zenodo.org/api/records/4595826/files/CUAD_v1.zip/content`
  - SHA-256: `88b694d99007d39777fa44cd72daf8297773d285dc3eab0091ba32078888d18e`
  - License: CC BY 4.0
  - CUAD data is never committed.
- Verification always uses `VerificationOptions(visual=False)`, and policies are sealed with `signer=None`.
- The text verdict drops findings whose rule ID is `contract-safe.visual.unavailable`. It is then `pass` if nothing non-pass remains, otherwise the worst remaining outcome.
- Edit offsets: days/months/years +15, percentage +1, money +1000.
- Anchor: up to 6 words immediately before the target inside the clause. If fewer than 3 words precede it, use up to 6 words after it. The anchor must occur exactly once in the clause.
- CLI defaults: `--formats docx,pdf`, `--seed 0`, `--workers os.cpu_count()`, `--case-timeout 120`. `--output` must be absent or empty.
- Clause-length buckets: `<1k` (<1000 chars), `1-2k` (1000–1999), `2-5k` (2000–4999), `>5k` (≥5000).
- `results.jsonl` is sorted by case key. Two runs with the same inputs and seed are byte-identical once `duration_s` is removed.
- Reports never contain contract text, only IDs, rule IDs and numbers. The CUAD attribution line is `Contains material from the Contract Understanding Atticus Dataset (CUAD) v1 by The Atticus Project, licensed under CC BY 4.0.`
- The CI synthetic gate requires zero false passes, every `authorized` case accepted, every operator applicable to at least one synthetic seed, and no runner errors. It must take under 60 s.
- Test files live in `tests/evaluation/` with `test_eval_*.py` names. The test tree has no `__init__.py`, so basenames must be unique.
- **Spec deviation (already decided):** Chinese PDFs use ReportLab's built-in CID font `STSong-Light`, not the 90-glyph test subset font. A probe showed the project's PDF adapter extracts it correctly, with clauses, dates, durations, money and percentages intact. Task 2 updates the spec text.

## Review Focus

1. **CUAD file names with non-ASCII or punctuation** (`LECLANCHÉ S.A. - …`, commas, `&`). These must load and get a usable `contract_id` and temp paths. The test lives in Task 4.
2. **Target values that are substrings of larger tokens** (`30 days` inside `130 days`). These must be rejected as non-unique, because policy matching counts raw substrings. The test lives in Task 6.
3. **English text outside Latin-1 in PDFs** (smart quotes, en/em dashes, ellipsis, `é` is fine, CJK in an English contract). Common punctuation must map to ASCII before `?` replacement, and the replacement count must be recorded. The test lives in Task 2.
4. **Very short or numberless contracts** (CUAD has 645-byte files). These must be recorded as not draftable with reason `no-unique-target`, never crash. The test lives in Task 6.
5. **A hung or crashing case.** It must become an error row while the rest of the run completes. The test lives in Task 7.

---

### Task 1: Package skeleton, shared models, tooling wiring

**Files:**
- Create: `evaluation/__init__.py`, `evaluation/models.py`, `evaluation/data/.gitkeep`
- Modify: `pyproject.toml` (`[tool.pytest.ini_options]` add `pythonpath = ["."]`)
- Modify: `.github/workflows/ci.yml` (ruff and mypy cover `evaluation`)
- Test: `tests/evaluation/test_eval_models.py`

**Interfaces:**
- Produces, in `evaluation/models.py`:
  - `class Expectation(StrEnum)`: `ACCEPT = "accept"`, `BLOCK = "block"`
  - `class Format(StrEnum)`: `DOCX = "docx"`, `PDF = "pdf"`
  - `Language = Literal["en", "zh"]`
  - `@dataclass(frozen=True) class AuthorizedEdit`: `before: str`, `after: str`, `paragraph_index: int`, `clause_label: str`, `heading: str`, `anchor: str`
  - `@dataclass(frozen=True) class SourceContract`: `source: str`, `contract_id: str`, `language: Language`, `paragraphs: tuple[str, ...]`, `declared_edit: AuthorizedEdit | None`
  - `@dataclass(frozen=True, order=True) class CaseKey`: `source: str`, `contract_id: str`, `format: str`, `operator: str`
  - `@dataclass(frozen=True) class NotApplicable`: `reason: str`
  - `@dataclass(frozen=True) class DraftFailure`: `source: str`, `contract_id: str`, `format: str`, `reason: str`
  - `@dataclass(frozen=True) class CaseResult`. Fields: `key: CaseKey`, `expectation: Expectation`, `text_verdict: str | None`, `raw_outcome: str | None`, `nonpass_rule_ids: tuple[str, ...]`, `edited_clause_chars: int | None`, `baseline_clause_count: int | None`, `duration_s: float`, `error: str | None`. Methods: `to_json() -> dict[str, object]`, plus the properties `false_pass: bool` and `accepted: bool`.
  - `VISUAL_UNAVAILABLE_RULE = "contract-safe.visual.unavailable"`
  - `def text_verdict(findings: Iterable[tuple[str, str]]) -> str`. It takes `(rule_id, outcome)` pairs, where outcome is `"pass"|"review"|"fail"`, and returns `"pass"|"review"|"fail"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_text_verdict_ignores_visual_unavailable() -> None:
    assert text_verdict([("contract-safe.visual.unavailable", "review"), ("x", "pass")]) == "pass"

def test_text_verdict_takes_worst_remaining() -> None:
    assert text_verdict([("a", "review"), ("b", "fail"), ("c", "pass")]) == "fail"
    assert text_verdict([("a", "review"), (VISUAL_UNAVAILABLE_RULE, "review")]) == "review"

def test_false_pass_only_for_block_cases_that_pass() -> None:
    # build CaseResult with expectation BLOCK/ACCEPT and text_verdict pass/review/fail/None
    # BLOCK+pass -> false_pass True; BLOCK+review/fail/None -> False
    # ACCEPT+pass -> accepted True; ACCEPT+review/None -> accepted False

def test_case_result_to_json_round_trips_key_fields() -> None:
    # to_json()["key"] == {"source":..,"contract_id":..,"format":..,"operator":..}
    # and contains every field name listed in the Interfaces block

def test_case_keys_sort_by_source_contract_format_operator() -> None: ...
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_models.py -q`. Expected: FAIL with `ModuleNotFoundError: evaluation`.
- [ ] **Step 3: Implement** `evaluation/models.py` as specified, and add `pythonpath = ["."]` to the pytest config. In `ci.yml`, change the lint line to `ruff check --select E4,E7,E9,F src tests evaluation` and the type check to `mypy src evaluation`.
- [ ] **Step 4: Run** the test file, then `mypy src evaluation` and `ruff check --select E4,E7,E9,F src tests evaluation`. Expected: all clean.
- [ ] **Step 5: Commit** `feat(eval): add evaluation package skeleton and shared models`.

### Task 2: Deterministic rendering

**Files:**
- Create: `evaluation/render.py`
- Modify: `docs/internal/specs/2026-10-08-evaluation-harness-design.md` (Rendering + Error handling: CID font replaces the subset font and the glyph check)
- Test: `tests/evaluation/test_eval_render.py`

**Interfaces:**
- Consumes: `Format`, `Language` (Task 1).
- Produces:
  - `def render_docx(paragraphs: Sequence[str], path: Path) -> Path`
  - `def render_pdf(paragraphs: Sequence[str], path: Path, *, language: Language) -> int`. It returns the number of replaced characters, which is always 0 for `zh`.
  - `def render(paragraphs: Sequence[str], path: Path, *, fmt: Format, language: Language) -> int`, which dispatches and returns 0 for DOCX.
  - `def latin1_safe(text: str) -> tuple[str, int]`
- DOCX:
  - Fixed core properties: author `ArtifactDiff evaluation`, created/modified `2000-01-01T00:00:00`.
  - Rewrite the ZIP with sorted entries, `date_time=(1980, 1, 1, 0, 0, 0)` and `ZIP_DEFLATED`.
- PDF:
  - A4, margins 54 pt, font size 10, leading 14, `invariant=1`, `pageCompression=1`.
  - English uses Helvetica with word wrap via `pdfmetrics.stringWidth`.
  - Chinese uses `UnicodeCIDFont("STSong-Light")` with per-character wrap.
  - A new page starts when y < margin; there is a blank line between paragraphs.
- `latin1_safe` first maps `“”„→"`, `‘’‚→'`, `–—→-`, `…→...` and NBSP→space, then replaces any remaining non-Latin-1 character with `?`. The count covers only the `?` replacements.

- [ ] **Step 1: Write the failing tests**

```python
def test_docx_render_is_byte_stable(tmp_path) -> None:
    # render_docx(PARAS, a); render_docx(PARAS, b); a.read_bytes() == b.read_bytes()

def test_pdf_render_is_byte_stable_for_en_and_zh(tmp_path) -> None: ...

def test_pdf_text_layer_round_trips_through_artifactdiff(tmp_path) -> None:
    # inspect_contract(render_pdf(...)) clause texts joined contain each paragraph (whitespace-normalized)
    # for zh: "第二条 付款条件" yields a clause with label normalized "第二条"

def test_long_paragraphs_wrap_across_pages(tmp_path) -> None:
    # 200 paragraphs of 400 chars -> PDF page count > 1, text still round-trips

def test_latin1_safe_maps_typography_then_counts_replacements() -> None:
    assert latin1_safe("“Agreement” – café … 中") == ('"Agreement" - café ... ?', 1)
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_render.py -q`. Expected: FAIL on import.
- [ ] **Step 3: Implement** `evaluation/render.py` and update the two spec paragraphs.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(eval): render paragraphs to deterministic DOCX and PDF`.

### Task 3: Synthetic seed corpus

**Files:**
- Create: `evaluation/corpus/synthetic/en-services.yaml`, `en-supply.yaml`, `zh-services.yaml`, `zh-purchase.yaml`
- Create: `evaluation/sources.py` (synthetic part)
- Test: `tests/evaluation/test_eval_sources.py`

**Interfaces:**
- Consumes: `SourceContract`, `AuthorizedEdit` (Task 1).
- Produces:
  - `SYNTHETIC_DIR = Path(__file__).parent / "corpus" / "synthetic"`
  - `def load_synthetic(directory: Path = SYNTHETIC_DIR) -> list[SourceContract]`, sorted by `contract_id`, with `source="synthetic"`.
- YAML schema: `id`, `language`, `license: CC0-1.0`, `paragraphs: [str]` and `edit: {before, after, clause_label, heading, anchor}`. The loader computes `paragraph_index` as the single paragraph containing `before`. Otherwise it raises `ValueError`.
- Content rules, which together make every Task 5 operator applicable to at least one seed:
  - Headed clauses: `Article I …` / `第一条 …`. Every clause body is under 800 characters.
  - The edited paragraph contains the target duration, one other number, a modal (`shall`/`应`) and at least two sentences.
  - Elsewhere there is a money amount, a date, another duration, a percentage, a company name (`… Inc.`/`… Ltd.`, or `甲方：…有限公司`), `shall`, `shall not`/`不得`, `may`/`可以`, and a paragraph with at least two sentences.
- Example edit: en `30 days → 45 days` in Payment Terms; zh `30天 → 45天` in `第二条 付款条件`.

- [ ] **Step 1: Write the failing tests**

```python
def test_synthetic_seeds_load_with_declared_edits() -> None:
    seeds = load_synthetic()
    assert [s.contract_id for s in seeds] == ["en-services", "en-supply", "zh-purchase", "zh-services"]
    assert all(s.declared_edit is not None and s.paragraphs[s.declared_edit.paragraph_index].count(s.declared_edit.before) == 1 for s in seeds)

def test_synthetic_declared_edits_draft_valid_policies(tmp_path) -> None:
    # for each seed and Format: render baseline, ArtifactDiffApplication(trust_store=TrustStore(identities=[])).draft_policy(...) does not raise

def test_seed_with_ambiguous_before_is_rejected(tmp_path) -> None:
    # YAML where `before` appears in two paragraphs -> ValueError
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_sources.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the loader and write the four seeds.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(eval): add synthetic seed contracts`.

### Task 4: CUAD fetch and load

**Files:**
- Modify: `evaluation/sources.py`
- Test: `tests/evaluation/test_eval_sources.py`

**Interfaces:**
- Produces:
  - `CUAD_URL`, `CUAD_SHA256` (verbatim from Global Constraints) and `CUAD_ATTRIBUTION`
  - `class CuadChecksumError(Exception)`
  - `def fetch_cuad(data_dir: Path, *, archive: Path | None = None, opener: Callable[[str], BinaryIO] = urllib.request.urlopen) -> Path`
  - `def split_paragraphs(text: str) -> tuple[str, ...]`, which splits on blank lines, collapses whitespace and drops empties.
  - `def load_cuad(text_dir: Path, *, limit: int | None, seed: int) -> list[SourceContract]`, with `source="cuad"`, `language="en"`, `declared_edit=None` and `contract_id` = the file stem.
- `fetch_cuad` steps:
  1. Download to `data_dir/raw/CUAD_v1.zip.part`, or copy `archive` when given.
  2. Verify SHA-256 and rename to `CUAD_v1.zip`.
  3. Extract only `CUAD_v1/full_contract_txt/*.txt` into a temp dir under `data_dir/generated/`, then rename it to `data_dir/generated/cuad/`.
  4. Return that path.
- On a checksum mismatch, raise `CuadChecksumError` and leave neither the `.part` file nor the generated dir behind.
- If `generated/cuad` already exists with 510 files, return it without downloading.
- Sampling: sort paths by name, `random.Random(seed).shuffle`, then take `limit`.

- [ ] **Step 1: Write the failing tests**

```python
def test_fetch_cuad_rejects_checksum_mismatch_and_leaves_nothing(tmp_path) -> None:
    # opener returns BytesIO(b"not a zip") -> CuadChecksumError; no files under tmp_path/raw or tmp_path/generated

def test_fetch_cuad_extracts_only_txt_from_verified_archive(tmp_path, monkeypatch) -> None:
    # build a small zip with full_contract_txt/a.txt + full_contract_pdf/a.pdf; monkeypatch evaluation.sources.CUAD_SHA256 to its digest
    # pass archive=...; result dir contains only a.txt

def test_split_paragraphs_collapses_whitespace() -> None:
    assert split_paragraphs("A  b\n c\n\n\n D\n") == ("A b c", "D")

def test_load_cuad_handles_unicode_and_punctuation_names(tmp_path) -> None:
    # files "LECLANCHÉ S.A. - JOINT DEVELOPMENT AND MARKETING AGREEMENT.txt", "A, B & C.txt"
    # load_cuad(..., limit=None, seed=0) returns both, contract_id == stem

def test_load_cuad_sampling_is_seeded_and_limited(tmp_path) -> None:
    # same seed -> same ids; different seed -> different order; limit respected
```

- [ ] **Step 2: Run** the tests. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** the CUAD part of `evaluation/sources.py`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(eval): fetch, verify and load CUAD v1`.

### Task 5: Mutation operators

**Files:**
- Create: `evaluation/mutations.py`
- Test: `tests/evaluation/test_eval_mutations.py`

**Interfaces:**
- Consumes: `AuthorizedEdit`, `NotApplicable`, `Expectation`, `Language`.
- Produces:
  - `Operator = Callable[[tuple[str, ...], AuthorizedEdit, Language, random.Random], tuple[str, ...] | NotApplicable]`
  - `@dataclass(frozen=True) class OperatorSpec`: `name: str`, `group: str`, `expectation: Expectation`, `fn: Operator`
  - `OPERATORS: tuple[OperatorSpec, ...]`, in the spec's table order, with `name`/`group`/`expectation` copied verbatim from the spec table. `group` is one of `baseline|application|same paragraph|elsewhere`.
  - `def operator_rng(seed: int, contract_id: str, operator: str) -> random.Random`, seeded with `int.from_bytes(sha256(f"{seed}\0{contract_id}\0{operator}").digest()[:8], "big")`.
  - `def apply_authorized(paragraphs, edit) -> tuple[str, ...]`
- Rules shared by all operators:
  - Every operator except `authorized`, `missing_edit` and `wrong_value` starts from `apply_authorized(...)`.
  - "Elsewhere" sites are paragraphs ≠ `edit.paragraph_index` that contain a match. The operator picks one with `rng.choice` over the sorted applicable indices.
  - Sentence split: en `(?<=[.;])\s+`, zh after `。`/`；`. A paragraph is applicable to a sentence operator only with ≥2 sentences.
  - "Increment a number" means: take the first `\d+` run inside the matched token and replace it with `int+1`, keeping commas and decimals.
  - The harness owns its patterns:
    - money: `(?:\$|USD|RMB|人民币)\s?\d[\d,]*(?:\.\d+)?` or `\d[\d,]*(?:\.\d+)?\s?(?:dollars|元|万元)`;
    - duration: `\d+\s?(?:days?|months?|years?|天|日|个月|年)`;
    - percentage: `\d+(?:\.\d+)?\s?(?:%|percent)`;
    - dates: ISO `\d{4}-\d{1,2}-\d{1,2}`, `\d{4}年\d{1,2}月\d{1,2}日`, and English `Month D, YYYY`. `date_change` increments the day, or decrements it if day+1 is invalid.
  - The language tables:

| | en | zh |
|---|---|---|
| unit change | `days`→`business days` | `天`→`个工作日` |
| negation insert | `shall `→`shall not ` (first `shall` not followed by `not`) | `应`→`不应` (first `应` not preceded by `不`) |
| negation remove | `shall not`→`shall` | `不得`→`可以` |
| modal swap | `may`→`shall` (word-bounded) | `可以`→`应当` |
| inserted sentence | ` The Supplier shall bear all related costs.` | `供方应承担全部相关费用。` |
| party | `(?:[A-Z][\w&.-]*\s){1,4}(?:Inc\.|LLC|Ltd\.|Corporation)` → insert ` Holdings` before the suffix | `(?:甲方|乙方)：([^；;。\n]+)` → append `控股` to the group |

  - `same_para_*` operators act only on `edit.paragraph_index`. `same_para_number` skips the authorized `after` value. `same_para_negation` uses the negation-insert table, and `same_para_sentence_delete` deletes the first sentence that does not contain `after`.

- [ ] **Step 1: Write the failing tests.** Use a fixed 4-paragraph en fixture and a zh fixture. Write one test per operator, asserting the exact resulting paragraph tuple. For example:

```python
def test_wrong_value_sets_target_one_beyond_declared() -> None:
    assert op("wrong_value")(PARAS, EDIT, "en", rng())[1] == PARAS[1].replace("30 days", "46 days")

def test_party_change_appends_holdings_before_suffix() -> None:
    assert "Acme Holdings Inc." in op("party_change")(PARAS, EDIT, "en", rng())[0]

def test_negation_insert_zh_skips_existing_bu_ying() -> None: ...

def test_every_operator_is_deterministic_for_same_seed() -> None:
    # for spec in OPERATORS: spec.fn(..., operator_rng(0,"c",spec.name)) twice -> equal

def test_operators_return_not_applicable_without_a_site() -> None:
    # paragraphs with no money -> money_change returns NotApplicable("no money site")

def test_operator_table_matches_spec() -> None:
    assert [s.name for s in OPERATORS] == ["authorized","missing_edit","wrong_value","unit_change",
      "same_para_number","same_para_negation","same_para_sentence_delete","money_change","date_change",
      "duration_change","percentage_change","party_change","negation_insert","negation_remove",
      "modal_swap","sentence_insert","sentence_delete","paragraph_delete"]
    assert [s.name for s in OPERATORS if s.expectation is Expectation.ACCEPT] == ["authorized"]
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_mutations.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `evaluation/mutations.py`.
- [ ] **Step 4: Run** the tests, then check that every operator applies to at least one seed: `python -c "from evaluation.sources import load_synthetic; from evaluation.mutations import *; ..."`. Expected: tests PASS, and there is no operator without a site. Add seed content in Task 3's YAML if one is missing.
- [ ] **Step 5: Commit** `feat(eval): add mutation operators with explicit expectations`.

### Task 6: Authorized-edit selection and policy preparation

**Files:**
- Create: `evaluation/targets.py`
- Test: `tests/evaluation/test_eval_targets.py`

**Interfaces:**
- Consumes: Tasks 1–3, plus `ArtifactDiffApplication`, `ClauseSelector`, `TrustStore`.
- Produces:
  - `@dataclass(frozen=True) class PreparedContract`. Fields: `contract: SourceContract`, `format: Format`, `edit: AuthorizedEdit`, `baseline_path: Path`, `sealed_policy_path: Path`, `edited_clause_chars: int`, `baseline_clause_count: int`, `pdf_replacements: int`.
  - `def choose_edit(contract: SourceContract, clauses: list[dict[str, object]]) -> AuthorizedEdit | str`. It takes the inspect payload's clauses and returns either an edit or a failure reason.
  - `def prepare(contract: SourceContract, fmt: Format, workdir: Path) -> PreparedContract | DraftFailure`
- `choose_edit` algorithm, in clause order then match order:
  - Candidates are: duration `\b(\d+) (days|months|years)\b`, then percentage `\b(\d+(?:\.\d+)?)%`, then money `\$\s?(\d[\d,]*)`.
  - Accept the first candidate whose matched text occurs exactly once in `"\n".join(paragraphs)` and exactly once in the clause text, using raw substring counts. Its `after` (offset per Global Constraints) must occur zero times in the document. Its anchor must satisfy the anchor rule.
  - Failure reasons, verbatim: `no-unique-target` and `no-unique-anchor`.
- `prepare`:
  1. Render the baseline into `workdir`.
  2. Run `inspect_contract(baseline, max_clauses=1000)`.
  3. Use `declared_edit` when present, otherwise `choose_edit`.
  4. Call `draft_policy`, `write_policy` and `seal_policy(..., signer=None)`.
  5. Any exception becomes `DraftFailure(reason=f"{type(e).__name__}: {e}"[:200])`.
- `edited_clause_chars` is the length of the clause containing the target.

- [ ] **Step 1: Write the failing tests**

```python
def test_choose_edit_rejects_substring_of_larger_token() -> None:
    # paragraphs contain "within 30 days" and "within 130 days" only -> "no-unique-target"

def test_choose_edit_uses_following_words_when_few_precede() -> None:
    # clause "30 days notice is required before termination." -> anchor "notice is required before termination."

def test_choose_edit_skips_candidate_whose_after_already_exists() -> None:
    # "30 days" and "45 days" both present -> falls through to the percentage candidate

def test_prepare_short_contract_records_no_unique_target(tmp_path) -> None:
    # 2-paragraph contract without numbers -> DraftFailure(reason="no-unique-target")

def test_prepare_synthetic_seed_produces_sealed_policy(tmp_path) -> None:
    # for each seed x Format: PreparedContract, sealed_policy_path exists, edited_clause_chars < 1000
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_targets.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `evaluation/targets.py`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(eval): choose authorized edits and prepare sealed policies`.

### Task 7: Runner

**Files:**
- Create: `evaluation/runner.py`
- Test: `tests/evaluation/test_eval_runner.py`

**Interfaces:**
- Consumes: Tasks 1, 2, 5 and 6.
- Produces:
  - `@dataclass(frozen=True) class RunResult`: `results: list[CaseResult]` (sorted by key), `draft_failures: list[DraftFailure]`, `not_applicable: list[tuple[CaseKey, str]]`, `pdf_replacements: int`
  - `def run_cases(contracts: Sequence[SourceContract], formats: Sequence[Format], *, seed: int, workers: int, case_timeout: float, workdir: Path, case_fn: Callable[[CaseJob], CaseResult] | None = None) -> RunResult`
  - `@dataclass(frozen=True) class CaseJob`: `key: CaseKey`, `expectation: Expectation`, `prepared: PreparedContract`, `candidate: tuple[str, ...]`, `workdir: Path`
  - `def execute_case(job: CaseJob) -> CaseResult`, a top-level function so it pickles. It renders the candidate, calls `verify_change(..., VerificationOptions(visual=False))`, then `list_findings` + `effective_verdict(...).raw_outcome`, and finally computes `text_verdict`.
- Flow:
  1. A `multiprocessing.Pool(workers)` runs `prepare` for each contract × format.
  2. Operators run in the parent; `NotApplicable` is recorded.
  3. Case jobs are dispatched with `apply_async`, and each `get(timeout=case_timeout)` is awaited.
  4. A timeout or exception becomes `CaseResult(error=..., text_verdict=None)`.
  5. Call `pool.terminate()` at the end.
  6. `case_fn` overrides `execute_case`, for tests only.

- [ ] **Step 1: Write the failing tests**

```python
def test_runner_synthetic_one_seed_end_to_end(tmp_path) -> None:
    # run_cases(load_synthetic()[:1], [Format.DOCX], seed=0, workers=2, case_timeout=60, workdir=tmp_path)
    # authorized case accepted; no BLOCK case false_pass; no errors

def test_runner_records_timeout_and_continues(tmp_path) -> None:
    # case_fn=_sleepy (module-level: sleeps 5s when operator=="money_change", else returns a stub pass result)
    # case_timeout=1 -> money_change row has error starting "timeout"; other rows present

def test_runner_results_are_deterministic_except_duration(tmp_path) -> None:
    # two runs into different workdirs -> [r.to_json() minus duration_s] equal
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_runner.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `evaluation/runner.py`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(eval): run cases in isolated, parallel, time-boxed workers`.

### Task 8: Metrics and report

**Files:**
- Create: `evaluation/report.py`
- Test: `tests/evaluation/test_eval_report.py`

**Interfaces:**
- Consumes: `RunResult`, `CaseResult`, `OPERATORS`, `CUAD_ATTRIBUTION`.
- Produces:
  - `@dataclass(frozen=True) class RunMetadata`. Fields: `source: str`, `cuad_sha256: str | None`, `artifactdiff_version: str` (from `importlib.metadata.version("artifactdiff")`), `git_commit: str | None` (`git rev-parse HEAD`, `None` on failure), `seed: int`, `limit: int | None`, `formats: tuple[str, ...]`, `options: dict[str, object]`.
  - `def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]`, which returns `(0.0, 0.0)` when `total == 0`.
  - `def clause_bucket(chars: int) -> str`
  - `def build_summary(run: RunResult, metadata: RunMetadata) -> dict[str, object]`
  - `def write_report(output: Path, run: RunResult, metadata: RunMetadata) -> None`. It writes `results.jsonl`, `summary.json` (sorted keys, indent 2) and `report.md`.
- Summary keys:
  - `metadata`, `counts` (cases, errors, draft_failures, not_applicable, pdf_replacements);
  - `false_pass` with `overall`/`by_format`/`by_operator`/`by_group`, each `{count, total, rate, ci95}`;
  - `blocked_split` (`{fail, review}` per operator);
  - `acceptance` with `{accepted, total, rate, ci95, false_block_reasons: [[rule_id, count], ...], by_clause_bucket}`;
  - `draftability` with `{draftable, total, rate, reasons}`;
  - `applicability` (per operator: applicable and n/a counts);
  - `duration_s` (`{median, p95}`).
- `report.md` contains:
  - a header with metadata;
  - a headline line `False passes: {count}/{total} ({rate:.2%}, 95% CI {lo:.2%}–{hi:.2%})`;
  - tables for the same sections;
  - a "Limitations" section stating visual evidence was disabled;
  - `CUAD_ATTRIBUTION` when the source is `cuad`.

- [ ] **Step 1: Write the failing tests**

```python
def test_wilson_interval_known_values() -> None:
    lo, hi = wilson_interval(0, 100); assert lo == 0.0 and abs(hi - 0.0370) < 1e-3
    lo, hi = wilson_interval(5, 100); assert abs(lo - 0.0215) < 1e-3 and abs(hi - 0.1118) < 1e-3

def test_clause_bucket_boundaries() -> None:
    assert [clause_bucket(n) for n in (999, 1000, 1999, 2000, 4999, 5000)] == ["<1k","1-2k","1-2k","2-5k","2-5k",">5k"]

def test_summary_counts_false_passes_and_ranks_false_block_reasons() -> None:
    # hand-built RunResult: 1 false pass, 2 false blocks with rule ids -> expected numbers

def test_errors_are_neither_passes_nor_accepted() -> None: ...

def test_report_contains_no_contract_text_and_cuad_attribution(tmp_path) -> None:
    # paragraphs include sentinel "ZZSENTINEL"; write_report -> sentinel absent from all three files;
    # source "cuad" -> CUAD_ATTRIBUTION in report.md
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation/test_eval_report.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `evaluation/report.py`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(eval): compute metrics and write JSON and Markdown reports`.

### Task 9: CLI, CI gate, README

**Files:**
- Create: `evaluation/__main__.py`, `evaluation/README.md`
- Modify: `README.md` (one "Evaluation" paragraph linking `evaluation/README.md`; no numbers yet)
- Test: `tests/evaluation/test_eval_cli.py`, `tests/evaluation/test_eval_synthetic_gate.py`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `def main(argv: Sequence[str] | None = None) -> int`
  - Subcommands:
    - `fetch-cuad [--data-dir evaluation/data] [--archive PATH]`
    - `run --source {synthetic,cuad} [--formats docx,pdf] [--limit N] [--seed 0] [--workers K] [--case-timeout 120] [--data-dir evaluation/data] --output DIR`
  - `run` exits 2 when `--output` is non-empty. For `--source cuad` it exits 2 when the CUAD text dir is missing, with a message naming `fetch-cuad`. It prints the summary headline and the report path.
- `evaluation/README.md` covers the commands, the metric definitions (copied from the spec's acceptance/false-pass section), the visual-off limitation and the CUAD attribution.

- [ ] **Step 1: Write the failing tests**

```python
def test_cli_rejects_non_empty_output(tmp_path) -> None:
    (tmp_path / "x").write_text("x"); assert main(["run", "--source", "synthetic", "--output", str(tmp_path)]) == 2

def test_cli_cuad_without_data_points_to_fetch(tmp_path, capsys) -> None:
    assert main(["run", "--source", "cuad", "--data-dir", str(tmp_path), "--output", str(tmp_path / "o")]) == 2
    assert "fetch-cuad" in capsys.readouterr().err

def test_synthetic_gate(tmp_path) -> None:
    # run_cases(load_synthetic(), [Format.DOCX, Format.PDF], seed=0, workers=os.cpu_count() or 2, case_timeout=60, workdir=tmp_path)
    # assert no errors; no false_pass; every authorized accepted;
    # every OPERATORS name has >=1 result row (applicable somewhere); elapsed < 60 s
```

- [ ] **Step 2: Run** `python -m pytest tests/evaluation -q`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** the CLI and the two READMEs.
- [ ] **Step 4: Verify** the following:
  - The full suite passes: `python -m pytest -q`.
  - `ruff check --select E4,E7,E9,F src tests evaluation` and `mypy src evaluation` are clean.
  - `python -m evaluation run --source synthetic --output build/eval/synthetic` prints `False passes: 0/…`.
  - CUAD smoke run: `python -m evaluation fetch-cuad`, then `python -m evaluation run --source cuad --limit 20 --output build/eval/cuad-20`. It must complete without errors. Record the headline numbers in the PR description, not in git.
- [ ] **Step 5: Commit** `feat(eval): add CLI, synthetic CI gate and documentation`.
