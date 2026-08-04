# Contract Corpus and 1.0 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the contract gate against a public synthetic golden/adversarial corpus and ship a reproducible, documented ArtifactDiff 1.0 release with demos, schemas, SBOM, and build provenance.

**Architecture:** Corpus source cases are declarative and generated deterministically into DOCX/PDF fixtures. A matrix runner compares actual verdicts with an explicit manifest and forbids false passes. Documentation, browser QA, package builds, CI, and release workflows are generated or tested from the same public interfaces users run.

**Tech Stack:** Python 3.11-3.13, pytest, ReportLab, python-docx, Playwright Chromium, Pillow, Hatchling/build, CycloneDX Python, GitHub Actions, LibreOffice in a pinned Linux visual job.

## Global Constraints

- This plan depends on `2026-08-04-contract-plugins-ci-hardening.md` being complete.
- Public corpus documents are synthetic and redistributable.
- Corpus covers Chinese, English, and bilingual contracts over DOCX-to-DOCX, PDF-to-PDF, and DOCX-to-PDF.
- Golden/adversarial corpus permits zero false `pass` outcomes.
- Pixel goldens run only in one pinned Linux renderer/font environment; semantic findings remain cross-platform stable.
- Python 3.11, 3.12, and 3.13 run on Windows, macOS, and Linux.
- ArtifactDiff remains installable and useful without a network service or account.
- Release artifacts include wheel, source distribution, SBOM, provenance, threat model, rule catalog, schemas, demo GIF, and synthetic example Review Bundle.
- ArtifactDiff declares version 1.0 only after every acceptance criterion and release gate passes.

---

### Task 1: Declarative synthetic contract corpus generator

**Files:**
- Create: `corpus/README.md`
- Create: `corpus/fonts/LICENSE`
- Create: `corpus/cases.yaml`
- Create: `scripts/generate_contract_corpus.py`
- Create: `tests/corpus/test_generator.py`
- Create: `tests/corpus/test_manifest.py`
- Create generated fixtures under: `corpus/generated/`
- Modify: `tests/factories.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `python scripts/generate_contract_corpus.py --manifest corpus/cases.yaml --output corpus/generated`
- Produces: `CorpusCase`, `CorpusVariant`, and one `case.json` beside each generated input set

- [ ] **Step 1: Add release-test dependencies and write failing manifest tests**

Add dev dependencies `"playwright>=1.50,<2"`, `"cyclonedx-bom>=5,<8"`, and retain ReportLab/Pillow already present.

```python
def test_every_corpus_case_has_explicit_expected_outcome() -> None:
    cases = load_corpus_manifest(Path("corpus/cases.yaml"))
    assert cases
    assert all(case.expected_outcome in {"pass", "review", "fail", "operational_error"} for case in cases)
    assert len({case.id for case in cases}) == len(cases)


def test_required_language_format_matrix_is_present() -> None:
    cases = load_corpus_manifest(Path("corpus/cases.yaml"))
    matrix = {(case.language, case.path) for case in cases if case.scenario == "exact-payment-edit"}
    assert matrix == {(language, path) for language in ("zh", "en", "zh-en") for path in ("docx-docx", "pdf-pdf", "docx-pdf")}
```

- [ ] **Step 2: Define the complete case manifest**

`cases.yaml` contains these scenario IDs for every applicable language/path combination, with an explicit policy relaxation list and expected outcome:

```yaml
- id: zh-docx-docx-exact-payment-edit
  language: zh
  path: docx-docx
  scenario: exact-payment-edit
  mutation: {payment_days: [30, 45]}
  expected_outcome: pass
  expected_rules: [expected.payment-term]
- id: zh-docx-docx-party-change
  language: zh
  path: docx-docx
  scenario: party-change
  mutation: {payment_days: [30, 45], party: [上海示例科技有限公司, 上海其他科技有限公司]}
  expected_outcome: fail
  expected_rules: [contract-safe.protected.parties]
```

The full manifest includes exact edit, missing edit, duplicate edit, wrong replacement, extra allowed-clause edit, out-of-scope body edit, party, money, currency, date, duration, percentage, clause deletion, page deletion, attachment deletion, header, footer, signature, seal, metadata, pagination reflow, unexplained font/position/image, ambiguous selector, hidden text, tracked revisions, comments, external link, malformed PDF/DOCX, encrypted PDF, ZIP bomb, traversal entry, and symlink escape.

- [ ] **Step 3: Implement deterministic DOCX/PDF generation**

Generate the baseline from one semantic `ContractSeed` and apply one named mutation to the candidate. ReportLab uses `canvas.Canvas(str(output), pagesize=A4, invariant=1, pageCompression=1)` and the bundled Liberation Sans font files in `corpus/fonts/`; include their upstream license text and provenance in `corpus/fonts/LICENSE`. DOCX output is rewritten as a sorted ZIP with every entry timestamp `(1980, 1, 1, 0, 0, 0)`, fixed permissions, and stable XML core properties. Do not use host locale, current time, random IDs, or installed system fonts.

```python
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def stable_zip(source_dir: Path, output: Path) -> None:
    with ZipFile(output, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(item for item in source_dir.rglob("*") if item.is_file()):
            info = ZipInfo(path.relative_to(source_dir).as_posix(), FIXED_ZIP_TIME)
            info.external_attr = 0o600 << 16
            archive.writestr(info, path.read_bytes(), compress_type=ZIP_DEFLATED, compresslevel=9)
```

- [ ] **Step 4: Generate and verify byte stability**

Run the generator twice into separate temporary roots and assert SHA-256 equality for every ordinary corpus fixture. Hostile ZIP and symlink cases are generated during tests rather than committed. `case.json` records license `CC0-1.0`, generator version, language, path, scenario, expected result, and source digests.

Run: `python -m pytest tests/corpus/test_generator.py tests/corpus/test_manifest.py -q`

Expected: PASS; all generated normal fixtures are byte-stable and contain no real person/company data.

- [ ] **Step 5: Commit corpus source and generated fixtures**

```bash
git add pyproject.toml corpus scripts/generate_contract_corpus.py tests/corpus tests/factories.py
git commit -m "test: add synthetic contract corpus"
```

---

### Task 2: Golden verdict, tamper, and adversarial release gates

**Files:**
- Create: `tests/golden/test_contract_corpus.py`
- Create: `tests/golden/test_finding_stability.py`
- Create: `tests/golden/test_bundle_tamper_matrix.py`
- Create: `tests/golden/test_adversarial_documents.py`
- Create: `tests/golden/snapshots/`
- Create: `scripts/run_golden_gate.py`

**Interfaces:**
- Produces: `python scripts/run_golden_gate.py --manifest corpus/cases.yaml --corpus corpus/generated --output build/golden-results.json`
- Produces machine result: case counts, false-pass count, false-fail count for exact fixtures, finding/bundle digest drift, duration, and failures

- [ ] **Step 1: Write the corpus runner test before its implementation**

```python
def test_public_corpus_has_no_false_pass(tmp_path: Path) -> None:
    result = run_golden_gate(Path("corpus/cases.yaml"), Path("corpus/generated"), tmp_path)
    assert result.false_passes == []
    assert result.exact_fixture_failures == []
    assert result.ambiguous_passes == []
    assert result.protected_region_passes == []
```

- [ ] **Step 2: Implement isolated case execution**

For each case, create a fresh input/output root, load its frozen local policy, invoke `ArtifactDiffApplication.verify_change`, independently verify the bundle, and compare raw outcome plus required rule IDs with the manifest. Never reuse a bundle or session across cases. Write canonical JSON sorted by case ID and return nonzero if any false pass, exact-fixture failure, ambiguity pass, protected-region pass, nondeterministic ID, or invalid bundle occurs.

- [ ] **Step 3: Add finding and digest snapshots**

Snapshot only canonical policy SHA-256, ordered `(finding_id, rule_id, outcome, location)` tuples, raw-verdict digest, and bundle manifest digest. Do not snapshot excerpts or machine paths. A deliberate schema/rule-version migration updates snapshots only through `python scripts/run_golden_gate.py --accept-schema-version 1.1`; the command rejects acceptance when any expected fail/review becomes pass.

- [ ] **Step 4: Add full tamper matrix**

Mutate one byte, delete, rename, duplicate, reorder, or replay every signed/hashed core and event component. Also test malicious recomputation of local hashes, assurance relabeling, policy signature reuse, manifest signature reuse, event copying across bundles, key revocation, wrong role, wrong purpose, and candidate replacement after verification. Verified bundles must reject every attack; local bundles must never claim adversarial tamper resistance.

- [ ] **Step 5: Run golden/adversarial gate twice**

Run: `python scripts/run_golden_gate.py --manifest corpus/cases.yaml --corpus corpus/generated --output build/golden-results-1.json`

Run: `python scripts/run_golden_gate.py --manifest corpus/cases.yaml --corpus corpus/generated --output build/golden-results-2.json`

Run: `python -m pytest tests/golden -q`

Expected: zero false passes, every exact fixture passes, both result files match after removing duration, every attack is detected, and ambiguous/protected changes never pass.

- [ ] **Step 6: Commit release gates**

```bash
git add tests/golden scripts/run_golden_gate.py
git commit -m "test: enforce zero-false-pass contract gate"
```

---

### Task 3: Pinned visual goldens and browser end-to-end review

**Files:**
- Create: `docker/visual-tests.Dockerfile`
- Create: `tests/visual/test_visual_goldens.py`
- Create: `tests/browser/test_review_desk.py`
- Create: `tests/browser/test_offline_report.py`
- Create: `tests/visual/goldens/`
- Create: `scripts/capture_contract_demo.py`
- Create: `docs/assets/artifactdiff-contract-demo.gif`

**Interfaces:**
- Produces: `docker build -f docker/visual-tests.Dockerfile -t artifactdiff-visual-tests .`
- Produces: `docker run --rm artifactdiff-visual-tests`
- Produces: `python scripts/capture_contract_demo.py --bundle examples/flagship/review-bundle --output docs/assets/artifactdiff-contract-demo.gif`

- [ ] **Step 1: Define a pinned Linux visual environment**

Use a Debian base image pinned by digest in the implementation commit. Install exact Debian package versions for LibreOffice Writer, fontconfig, Liberation Sans, and Chromium; copy the repository; install the wheel and Playwright Python package without downloading a second browser. Write `/environment.json` with OS, package, LibreOffice, Chromium, font-file, Python, ArtifactDiff, and renderer versions. The test fails if any recorded version differs from the checked-in `tests/visual/environment.json`.

- [ ] **Step 2: Write visual-golden tests**

Render the exact-payment, pagination-reflow, protected-signature, and cross-format fixtures. Compare page dimensions and pixels against committed PNG goldens with per-channel threshold `16` and changed-pixel tolerance `0.001`; output heatmaps on failure. Assert semantic findings and IDs exactly, independent of pixel tolerance.

```python
def assert_visual_golden(actual: Path, expected: Path) -> None:
    change, _ = compare_images(expected, actual, output_dir=actual.parent / "diagnostic", threshold=16, tile_size=32)
    assert change.changed_pixel_ratio <= 0.001
```

- [ ] **Step 3: Write browser security and workflow tests**

Launch the review server on a random loopback port and Playwright Chromium with all external network requests aborted. Test token exchange, policy wizard, contract-safe relaxation display, finding keyboard navigation, raw/effective verdict, signed approval through a fake server-side provider, fail approval absence, XSS text, responsive widths 320/768/1440, reload, and shutdown.

```python
page.on("request", lambda request: pytest.fail(request.url) if not request.url.startswith("http://127.0.0.1:") else None)
```

- [ ] **Step 4: Capture the reproducible demo GIF**

The script uses the synthetic flagship bundle, a fixed 1280x800 viewport, reduced motion, and seven named frames: policy summary, contract-safe protections, exact edit finding, visual evidence, review finding, signed approval, effective pass. Store each PNG, then use Pillow with fixed 900 ms duration, loop `0`, and an adaptive 128-color palette to write the GIF. The script never records a real desktop or real contract.

- [ ] **Step 5: Run visual and browser gates**

Run: `python -m pytest tests/browser -q`

Run: `docker build -f docker/visual-tests.Dockerfile -t artifactdiff-visual-tests .`

Run: `docker run --rm artifactdiff-visual-tests`

Expected: browser tests make zero external requests; pinned visual goldens pass; demo GIF is reproducible and contains no clipping, overlap, missing evidence, or unreadable contrast.

- [ ] **Step 6: Commit visual QA and demo**

```bash
git add docker tests/browser tests/visual scripts/capture_contract_demo.py docs/assets/artifactdiff-contract-demo.gif
git commit -m "test: verify contract review visuals"
```

---

### Task 4: User, security, rule, schema, and plugin documentation

**Files:**
- Create: `README.md`
- Create: `LICENSE`
- Create: `SECURITY.md`
- Create: `docs/quickstart-contract-edit.md`
- Create: `docs/threat-model.md`
- Create: `docs/rule-catalog.md`
- Create: `docs/policy-reference.md`
- Create: `docs/review-bundle.md`
- Create: `docs/plugin-api.md`
- Create: `docs/assurance-model.md`
- Create: `docs/privacy.md`
- Create: `docs/schema/`
- Create: `scripts/export_schemas.py`
- Create: `tests/docs/test_readme_commands.py`
- Create: `tests/docs/test_schema_drift.py`
- Create: `tests/docs/test_links.py`
- Create: `examples/flagship/README.md`
- Create generated example under: `examples/flagship/`

**Interfaces:**
- Produces: `python scripts/export_schemas.py --output docs/schema`
- Produces a two-minute local tutorial: install, draft/freeze policy, edit candidate, verify, review, approve, independently verify bundle

- [ ] **Step 1: Export all independently versioned schemas**

Export Pydantic JSON Schema for Contract IR, Policy, Frozen/Sealed Policy, Finding, Raw/Effective Verdict, Comparison, Bundle Manifest, events, and Plugin Manifest. Sort keys, use UTF-8, and include `$id` values under `https://artifactdiff.dev/schema/1.0/`. `test_schema_drift.py` exports into a temporary directory and byte-compares every checked-in schema.

- [ ] **Step 2: Write the flagship quickstart and executable README snippets**

The first README screen contains:

````markdown
# ArtifactDiff

Regression tests for contract edits made by humans and AI agents.

```bash
pipx install artifactdiff
artifactdiff policy create contract.docx -o change-policy.yaml
artifactdiff policy seal contract.docx change-policy.yaml -o change-policy.sealed.json
artifactdiff verify contract.docx edited.docx --policy change-policy.sealed.json --output review-bundle
artifactdiff review review-bundle
```
````

Document local versus verified versus enterprise assurance without overstating offline chronology. The verified tutorial must sign the policy, run `artifactdiff session open`, give only the emitted candidate workspace to the Agent, and verify with `--session` plus a manifest signer. Include the exact 30-to-45-day tutorial, all CLI/MCP tools, GitHub Action, supported format paths/languages, privacy modes, LibreOffice behavior, 100 MiB/500-page/DOCX archive limits, exit codes, and explicit OCR/PPTX/XLSX/legal-advice exclusions. `test_readme_commands.py` extracts each shell block, substitutes synthetic paths, and runs non-destructive commands.

- [ ] **Step 3: Write threat model, rule catalog, and privacy docs**

Threat model assets: malicious candidate, malicious policy rewrite, post-verification tamper, Agent self-approval, plugin supply chain, path escape, ZIP bomb, XSS, localhost cross-origin request, key disclosure, renderer nondeterminism, metadata leakage, and untrusted local administrator. For each, state protected assets, boundary, mitigation, residual risk, and assurance level.

Rule catalog lists every stable `contract-safe.*` and `expected.*` rule ID, version, trigger, outcome, approvability, evidence, and remediation. Privacy docs give an exact file table for minimal/full/sealed modes.

- [ ] **Step 4: Document Review Bundle and plugin compatibility**

Document manifest hashing exclusions, signature purposes, event chain, independent verification, local-assurance limitation, archive packing, schema migration, old-verifier lookup, seven entry-point groups, manifest disclosure fields, and the prohibition on plugin verdicts. Include complete minimal parser and enterprise-attestation plugin examples that pass the plugin contract tests.

- [ ] **Step 5: Create MIT license and synthetic example bundle**

Use the canonical MIT License with `Copyright (c) 2026 wfengq`. Generate one minimal local bundle and one verified review bundle from the flagship synthetic contract; include the public test keys only, mark them `TEST KEY - DO NOT USE`, and verify both examples in `tests/docs/test_readme_commands.py`.

- [ ] **Step 6: Run documentation tests and commit**

Run: `python scripts/export_schemas.py --output docs/schema`

Run: `python -m pytest tests/docs -q`

Expected: all links resolve locally or to allowlisted project URLs, schemas have no drift, commands execute, and example bundles verify.

```bash
git add README.md LICENSE SECURITY.md docs scripts/export_schemas.py tests/docs examples/flagship
git commit -m "docs: publish contract verification workflow"
```

---

### Task 5: Cross-platform CI, SBOM, provenance, and release workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/visual.yml`
- Create: `.github/workflows/release.yml`
- Create: `.github/dependabot.yml`
- Create: `release/maintainer-release-key.asc`
- Create: `scripts/check_release.py`
- Create: `tests/release/test_workflows.py`
- Create: `tests/release/test_package.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `python scripts/check_release.py dist/`
- Produces release assets: `.whl`, `.tar.gz`, `.cdx.json`, provenance attestations, `artifactdiff-contract-demo.gif`, and synthetic example bundle archive

- [ ] **Step 1: Write failing workflow-policy tests**

```python
def test_ci_matrix_covers_required_python_and_operating_systems() -> None:
    workflow = load_workflow(".github/workflows/ci.yml")
    matrix = workflow["jobs"]["test"]["strategy"]["matrix"]
    assert set(matrix["os"]) == {"ubuntu-latest", "macos-latest", "windows-latest"}
    assert set(matrix["python-version"]) == {"3.11", "3.12", "3.13"}


def test_release_uses_trusted_publishing_and_attestation() -> None:
    text = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "actions/attest-build-provenance@v2" in text
    assert "password:" not in text
```

- [ ] **Step 2: Implement cross-platform semantic CI**

Use `actions/checkout@v4` and `actions/setup-python@v5`. Matrix all three operating systems and Python versions. Install `-e .[dev]`, then run Ruff, mypy strict, all non-browser/non-visual tests, golden corpus, build, and installed-wheel CLI/MCP smoke tests. Upload only failed diagnostic logs with `actions/upload-artifact@v4` and a seven-day retention.

- [ ] **Step 3: Implement pinned visual CI**

On changes affecting parsing, rendering, review web, corpus, or visual tests, build `docker/visual-tests.Dockerfile`, run visual/browser tests inside it, regenerate the demo into a temporary path, and byte-compare it with the committed GIF. Upload heatmaps/screenshots only on failure.

- [ ] **Step 4: Implement release workflow and artifact checks**

Trigger only on tags matching `v*`. `scripts/check_release.py` requires tag `v1.0.0` to match `project.version == "1.0.0"`, verifies the tag signature via `git tag -v`, reruns all nonvisual and container visual gates, builds wheel/sdist, installs each into a clean virtual environment, verifies example bundles, generates CycloneDX JSON SBOM, and rejects missing/unexpected files.

The workflow imports the checked-in maintainer public release key, verifies the signed tag, and uses GitHub environment `pypi`, `id-token: write`, `actions/attest-build-provenance@v2`, and `pypa/gh-action-pypi-publish@release/v1`. It invokes the GitHub-hosted runner's `gh release create`/`gh release upload` commands with `GITHUB_TOKEN` to attach non-PyPI demo/example assets. No long-lived PyPI token or third-party release action is configured.

- [ ] **Step 5: Set 1.0 metadata only after local release checks pass**

Change `project.version` from `0.1.0` to `1.0.0`, add classifiers for Python 3.11-3.13 and OS Independent, set MIT license metadata, project URLs, README, keywords, and `artifactdiff`/`artifactdiff-mcp` scripts. Build and inspect both archives to ensure all templates, assets, schemas, license, typing marker, and no test/private-key/build files are included.

- [ ] **Step 6: Test workflows and package contents**

Run: `python -m pytest tests/release -q`

Run: `python -m build`

Run: `python scripts/check_release.py dist/ --skip-tag-check`

Expected: workflow policy, package contents, clean-environment installs, CLI/MCP discovery, SBOM, examples, and provenance-input manifest checks PASS.

- [ ] **Step 7: Commit release automation**

```bash
git add .github release/maintainer-release-key.asc pyproject.toml scripts/check_release.py tests/release
git commit -m "build: prepare ArtifactDiff 1.0 release"
```

---

### Task 6: Final acceptance verification and signed release candidate

**Files:**
- Modify only if a failing acceptance test requires a tested fix.

**Interfaces:**
- Consumes every public CLI, Python, MCP, UI, plugin, action, bundle, and release interface from Plans 1-5 and Tasks 1-5 above.

- [ ] **Step 1: Start from a clean checkout and install the built wheel**

Run: `git status --short`

Expected: empty.

Run: `python -m build`

Run in a fresh virtual environment: `python -m pip install dist/artifactdiff-1.0.0-py3-none-any.whl`

Expected: installation succeeds without editable-source imports.

- [ ] **Step 2: Run static, type, unit, integration, corpus, docs, and release checks**

Run: `python -m ruff check src tests scripts`

Run: `python -m mypy src/artifactdiff`

Run: `python -m pytest -q -m "not browser and not visual"`

Run: `python scripts/run_golden_gate.py --manifest corpus/cases.yaml --corpus corpus/generated --output build/golden-results.json`

Run: `python scripts/check_release.py dist/ --skip-tag-check`

Expected: every command exits `0`; golden results report zero false passes.

- [ ] **Step 3: Run pinned browser and visual checks**

Run: `docker build -f docker/visual-tests.Dockerfile -t artifactdiff-visual-tests .`

Run: `docker run --rm artifactdiff-visual-tests`

Expected: browser, visual, offline-network, demo-byte, and renderer-manifest gates PASS.

- [ ] **Step 4: Exercise the installed flagship workflow**

Using only installed console scripts and `examples/flagship`, create a policy, freeze it locally, create and authorize a verified policy with the test identity, open a verified edit session, apply the 30-to-45-day fixture edit, verify all three supported format paths, inspect review findings, approve the pagination review, verify bundles, and pack/decrypt a sealed archive. Assert expected raw/effective outcomes and independent digest verification after copying bundles to a second directory.

- [ ] **Step 5: Verify CLI, MCP, Action, privacy, and failure semantics**

Run all help commands and initialize an MCP in-memory session to discover exactly ten tools. Simulate the composite Action for pass/review/fail. Inspect minimal/full/sealed archives for prohibited files. Corrupt one core file and one event and confirm exit `2`; run review/fail candidates and confirm exit `1`; run exact/local and approved/effective passes and confirm exit `0`.

- [ ] **Step 6: Record the release candidate evidence**

Write `build/release-candidate.json` with Git commit, Python/OS matrix links, package hashes, SBOM hash, golden summary hash, visual environment hash, example bundle hashes, demo GIF hash, and every acceptance check result. Sign its SHA-256 with an `archive_signer` test/release identity and verify the signature independently.

- [ ] **Step 7: Create a signed tag only after every preceding step passes**

```bash
git tag -s v1.0.0 -m "ArtifactDiff 1.0.0"
git tag -v v1.0.0
```

Expected: tag signature verifies and points to a clean commit containing all release artifacts except generated `build/` and `dist/` outputs.

---

## Plan 6 completion gate

- [ ] Public corpus is deterministic, synthetic, redistributable, and covers the declared matrix.
- [ ] Golden/adversarial gates report zero false passes and stable IDs/digests.
- [ ] Pinned Linux pixel goldens and cross-platform semantic tests pass.
- [ ] Browser review and offline report tests make no external requests.
- [ ] Quickstart works from the built wheel without an account or network service.
- [ ] Threat model, rules, privacy, schemas, plugin API, and assurance limits are documented.
- [ ] Wheel, sdist, SBOM, provenance, demo GIF, and example bundle pass release inspection.
- [ ] Version becomes `1.0.0` and signed tag `v1.0.0` is created only after every gate passes.
