# Contract Policy and Verdict Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compile YAML, JSON, Python, and future MCP inputs into one frozen policy and deterministically produce fail-closed `pass`, `review`, or `fail` raw verdicts for constrained contract edits.

**Architecture:** Add separate `policy` and `verification` packages. Policy parsing, canonicalization, baseline binding, fact extraction, rule evaluation, and orchestration remain independent units. The verification service loads both formats independently, uses Contract IR for authority decisions, and reuses a refactored visual-page comparator without changing legacy comparison semantics.

**Tech Stack:** Python 3.11-3.13, Pydantic 2, PyYAML 6, standard-library JSON/SHA-256, existing Contract IR and visual engine, pytest.

## Global Constraints

- This plan depends on `2026-08-04-contract-ir-foundation.md` being complete.
- The policy is defined and frozen against the baseline before editing.
- `contract-safe` is the default profile and denies implicit authorization.
- Policy expressions are data; arbitrary Python, shell, templates, callbacks, and unbounded regular expressions are rejected.
- Exact expected edits can pass; extra in-scope edits review; out-of-scope and protected changes fail.
- `review` blocks delivery by default.
- ArtifactDiff never uses an LLM for the final verdict.
- Canonical policy bytes, findings, IDs, and verdicts are deterministic.
- Legacy `compare` rejects mismatched formats exactly as it does before this plan.
- Contract verification always enforces document/resource limits; legacy `compare --force` does not carry into `VerificationOptions`.

---

### Task 1: Strict policy schema, YAML/JSON loading, and canonical bytes

**Files:**
- Create: `src/artifactdiff/policy/__init__.py`
- Create: `src/artifactdiff/policy/models.py`
- Create: `src/artifactdiff/policy/canonical.py`
- Create: `src/artifactdiff/policy/io.py`
- Create: `tests/unit/policy/test_models.py`
- Create: `tests/unit/policy/test_canonical.py`
- Create: `tests/unit/policy/test_io.py`
- Modify: `pyproject.toml`
- Modify: `src/artifactdiff/errors.py`

**Interfaces:**
- Consumes: `ClauseSelector`, `StrictModel`
- Produces: `ExactReplace`, `ExpectedRule`, `AllowRule`, `ProtectedTarget`, `VisualPolicy`, `MetadataPolicy`, `EvidenceMode`, `EvidencePolicy`, `PolicyPluginRequirement`, `PolicyBaseline`, `ContractPolicy`, `FrozenPolicy`
- Produces: `canonical_policy_bytes(policy: ContractPolicy) -> bytes`
- Produces: `policy_digest(policy: ContractPolicy) -> str`
- Produces: `load_policy(path: Path) -> ContractPolicy`
- Produces: `write_policy(policy: ContractPolicy, path: Path) -> Path`
- Produces: `PolicyValidationError(InputValidationError)`

- [ ] **Step 1: Add PyYAML and write failing strict-schema tests**

Add `"PyYAML>=6.0,<7"` to runtime dependencies.

```python
def test_policy_defaults_to_contract_safe_and_minimal() -> None:
    policy = ContractPolicy(baseline=PolicyBaseline(sha256="a" * 64, format="docx"))
    assert policy.profile == "contract-safe"
    assert policy.visual.on_unavailable == "review"
    assert policy.evidence.mode is EvidenceMode.MINIMAL


def test_policy_rejects_executable_or_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ContractPolicy.model_validate({
            "baseline": {"sha256": "a" * 64, "format": "docx"},
            "callback": "os.system('x')",
        })
```

- [ ] **Step 2: Run policy tests and verify import failure**

Run: `python -m pytest tests/unit/policy/test_models.py -q`

Expected: FAIL because `artifactdiff.policy` does not exist.

- [ ] **Step 3: Implement the versioned policy models**

```python
class EvidenceMode(StrEnum):
    MINIMAL = "minimal"
    FULL = "full"
    SEALED = "sealed"


class ExactReplace(StrictModel):
    type: Literal["exact_replace"] = "exact_replace"
    before: str = Field(min_length=1, max_length=10_000)
    after: str = Field(min_length=1, max_length=10_000)
    occurrences: int = Field(default=1, ge=1, le=100)


class ExpectedRule(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    selector: ClauseSelector
    operation: ExactReplace


class AllowRule(StrictModel):
    selector: ClauseSelector
    kinds: frozenset[Literal["added", "removed", "modified", "moved"]]


class ProtectedTarget(StrEnum):
    PARTIES = "parties"
    MONEY = "money"
    CURRENCY = "currency"
    DATES = "dates"
    DURATIONS = "durations"
    PERCENTAGES = "percentages"
    HEADERS = "headers"
    FOOTERS = "footers"
    SIGNATURES = "signatures"
    SEALS = "seals"
    ATTACHMENTS = "attachments"


class VisualPolicy(StrictModel):
    explained_regions: Literal["pass"] = "pass"
    pagination_reflow: Literal["review", "fail"] = "review"
    protected_region_change: Literal["fail"] = "fail"
    on_unavailable: Literal["review", "fail"] = "review"
    layout_envelope_padding_points: float = Field(default=6.0, ge=0.0, le=72.0)


class EvidencePolicy(StrictModel):
    mode: EvidenceMode = EvidenceMode.MINIMAL


class MetadataPolicy(StrictModel):
    non_business_change: Literal["review", "ignore"] = "review"


class PolicyBaseline(StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    format: Literal["pdf", "docx"]


class PolicyPluginRequirement(StrictModel):
    version: str = Field(min_length=1, max_length=128)
    distribution: str = Field(min_length=1, max_length=128)
    allow_network: bool = False
    allow_model: bool = False


class ContractPolicy(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["contract-safe"] = "contract-safe"
    profile_version: Literal["1.0"] = "1.0"
    baseline: PolicyBaseline
    expect: list[ExpectedRule] = Field(default_factory=list, max_length=100)
    allow: list[AllowRule] = Field(default_factory=list, max_length=100)
    protect: frozenset[ProtectedTarget] = Field(default_factory=lambda: frozenset(ProtectedTarget))
    visual: VisualPolicy = Field(default_factory=VisualPolicy)
    metadata: MetadataPolicy = Field(default_factory=MetadataPolicy)
    evidence: EvidencePolicy = Field(default_factory=EvidencePolicy)
    required_plugins: dict[str, PolicyPluginRequirement] = Field(default_factory=dict)


class FrozenPolicy(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    policy: ContractPolicy
    canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assurance: Literal["local"] = "local"
```

- [ ] **Step 4: Write failing canonical-equivalence tests**

```python
def test_yaml_json_and_python_produce_identical_canonical_bytes(tmp_path: Path) -> None:
    python_policy = payment_policy()
    yaml_path = write_yaml_with_reordered_keys(tmp_path / "policy.yaml", python_policy)
    json_path = write_json_with_reordered_keys(tmp_path / "policy.json", python_policy)
    assert canonical_policy_bytes(load_policy(yaml_path)) == canonical_policy_bytes(load_policy(json_path))
    assert canonical_policy_bytes(load_policy(json_path)) == canonical_policy_bytes(python_policy)


def test_sets_and_unicode_are_canonicalized() -> None:
    left = payment_policy(protect=["money", "dates"], heading="付款条件")
    right = payment_policy(protect=["dates", "money"], heading=unicodedata.normalize("NFD", "付款条件"))
    assert canonical_policy_bytes(left) == canonical_policy_bytes(right)
```

- [ ] **Step 5: Implement canonical JSON and safe file loading**

Normalize every string to Unicode NFC, convert paths to forward-slash strings, sort mapping keys, sort set-like fields, preserve rule-list order, encode UTF-8, and serialize with separators `(",", ":")` and `ensure_ascii=False`. Reject YAML aliases, custom tags, multi-document streams, non-string mapping keys, and files over 1 MiB.

```python
def canonical_policy_bytes(policy: ContractPolicy) -> bytes:
    normalized = _normalize(policy.model_dump(mode="json"), path=())
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def policy_digest(policy: ContractPolicy) -> str:
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()
```

`write_policy` writes canonical JSON for `.json` and `yaml.safe_dump(payload, allow_unicode=True, sort_keys=True)` for `.yaml`/`.yml` through an adjacent temporary file followed by `Path.replace`.

- [ ] **Step 6: Run policy model, IO, and canonicalization tests**

Run: `python -m pytest tests/unit/policy -q`

Expected: PASS; invalid tags, oversized files, duplicate expected-rule IDs, and unknown fields are rejected with `PolicyValidationError`.

- [ ] **Step 7: Commit policy schema and canonicalization**

```bash
git add pyproject.toml src/artifactdiff/errors.py src/artifactdiff/policy tests/unit/policy
git commit -m "feat: canonicalize strict contract policies"
```

---

### Task 2: Baseline validation, policy drafting, and local freezing

**Files:**
- Create: `src/artifactdiff/policy/service.py`
- Create: `src/artifactdiff/policy/profile.py`
- Create: `tests/unit/policy/test_service.py`
- Create: `tests/integration/policy/test_freeze_policy.py`

**Interfaces:**
- Consumes: `ContractDocument`, `resolve_baseline`, policy models and canonical bytes
- Produces: `draft_exact_replace_policy(baseline: ContractDocument, selector: ClauseSelector, *, before: str, after: str, rule_id: str) -> ContractPolicy`
- Produces: `validate_policy(baseline: ContractDocument, policy: ContractPolicy) -> None`
- Produces: `freeze_policy(baseline: ContractDocument, policy: ContractPolicy) -> FrozenPolicy`
- Produces: `write_frozen_policy(policy: FrozenPolicy, path: Path) -> Path`
- Produces: `load_frozen_policy(path: Path) -> FrozenPolicy`

- [ ] **Step 1: Write failing baseline-binding and selector tests**

```python
def test_freeze_binds_policy_to_exact_baseline(contract: ContractDocument) -> None:
    policy = payment_policy_for(contract)
    frozen = freeze_policy(contract, policy)
    assert frozen.policy.baseline.sha256 == contract.source.sha256
    assert frozen.canonical_sha256 == policy_digest(policy)
    assert frozen.assurance == "local"


def test_freeze_rejects_ambiguous_baseline_selector(duplicated_payment_contract: ContractDocument) -> None:
    with pytest.raises(PolicyValidationError, match="must resolve exactly once"):
        freeze_policy(duplicated_payment_contract, payment_policy_for(duplicated_payment_contract))
```

- [ ] **Step 2: Run tests and verify missing-service failure**

Run: `python -m pytest tests/unit/policy/test_service.py tests/integration/policy/test_freeze_policy.py -q`

Expected: FAIL because policy service functions do not exist.

- [ ] **Step 3: Implement contract-safe profile defaults and explicit relaxation validation**

Define `CONTRACT_SAFE_PROFILE_VERSION = "1.0"`. Validation rejects an empty `expect` list for the flagship workflow, duplicate rule IDs, selector occurrence mismatch, a baseline format/hash mismatch, unsupported required plugin constraints, and any `allow` rule not resolvable exactly once. The default protected set is every `ProtectedTarget`; removing an item is permitted only because that absence is visible in canonical policy bytes.

```python
def validate_policy(baseline: ContractDocument, policy: ContractPolicy) -> None:
    if policy.baseline.sha256 != baseline.source.sha256 or policy.baseline.format != baseline.source.format:
        raise PolicyValidationError("policy baseline does not match the inspected contract")
    if not policy.expect:
        raise PolicyValidationError("contract-safe requires at least one exact expected operation")
    for rule in [*policy.expect, *policy.allow]:
        resolution = resolve_baseline(baseline, rule.selector)
        if resolution.status is not SelectorResolutionStatus.UNIQUE:
            raise PolicyValidationError(f"selector must resolve exactly once: {rule.selector}")
```

- [ ] **Step 4: Implement deterministic policy drafting and freezing**

Drafting copies the exact baseline clause label, heading, ancestor path, fingerprint, and anchor into the selector. It verifies that `before` occurs exactly `operation.occurrences` times in that clause before returning the draft. Freezing validates and hashes the canonical policy; it adds no timestamp or machine-specific path.

```python
def freeze_policy(baseline: ContractDocument, policy: ContractPolicy) -> FrozenPolicy:
    validate_policy(baseline, policy)
    return FrozenPolicy(policy=policy, canonical_sha256=policy_digest(policy))
```

- [ ] **Step 5: Run freeze and deterministic serialization tests**

Run: `python -m pytest tests/unit/policy tests/integration/policy -q`

Expected: PASS; repeated freezes are byte-identical and fail on a changed baseline hash.

- [ ] **Step 6: Commit baseline policy freezing**

```bash
git add src/artifactdiff/policy tests/unit/policy tests/integration/policy
git commit -m "feat: freeze policies against contract baselines"
```

---

### Task 3: Contract change facts independent of authorization

**Files:**
- Create: `src/artifactdiff/verification/__init__.py`
- Create: `src/artifactdiff/verification/models.py`
- Create: `src/artifactdiff/verification/facts.py`
- Create: `tests/unit/verification/test_facts.py`

**Interfaces:**
- Consumes: `ContractDocument`, selector scoring and normalized fingerprints
- Produces: `ClauseChangeKind`, `ClauseChange`, `EntityChange`, `RegionChange`, `FeatureChange`, `ContractChangeSet`
- Produces: `diff_contracts(baseline: ContractDocument, candidate: ContractDocument) -> ContractChangeSet`

- [ ] **Step 1: Write failing observed-fact tests**

```python
def test_diff_contracts_records_exact_payment_text_and_duration_change() -> None:
    facts = diff_contracts(contract(days=30), contract(days=45))
    assert len(facts.clause_changes) == 1
    change = facts.clause_changes[0]
    assert change.kind is ClauseChangeKind.MODIFIED
    assert (change.before_text, change.after_text) == (payment_text(30), payment_text(45))
    assert {(item.kind.value, item.before_value, item.after_value) for item in facts.entity_changes} == {
        ("duration", "30 day", "45 day")
    }


def test_diff_contracts_keeps_ambiguous_pairing_unresolved() -> None:
    facts = diff_contracts(contract_with_duplicate_sections(), modified_duplicate_contract())
    assert facts.unresolved_clause_ids
```

- [ ] **Step 2: Run the test and verify missing verification package**

Run: `python -m pytest tests/unit/verification/test_facts.py -q`

Expected: FAIL because the verification models do not exist.

- [ ] **Step 3: Implement portable fact models**

```python
class ClauseChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    MOVED = "moved"


class ClauseChange(StrictModel):
    id: str
    kind: ClauseChangeKind
    before_clause_id: str | None = None
    after_clause_id: str | None = None
    before_text: str | None = None
    after_text: str | None = None
    before_evidence: list[EvidenceRef] = Field(default_factory=list)
    after_evidence: list[EvidenceRef] = Field(default_factory=list)


class EntityChange(StrictModel):
    id: str
    kind: EntityKind
    before_value: str | None = None
    after_value: str | None = None
    clause_change_id: str


class RegionChange(StrictModel):
    id: str
    kind: ProtectedRegionKind
    before_fingerprint: str | None = None
    after_fingerprint: str | None = None


class FeatureChange(StrictModel):
    id: str
    kind: DocumentFeatureKind
    before_fingerprint: str | None = None
    after_fingerprint: str | None = None
    business_relevance: Literal["business", "non_business"]


class ContractChangeSet(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    baseline_sha256: str
    candidate_sha256: str
    clause_changes: list[ClauseChange] = Field(default_factory=list)
    entity_changes: list[EntityChange] = Field(default_factory=list)
    region_changes: list[RegionChange] = Field(default_factory=list)
    feature_changes: list[FeatureChange] = Field(default_factory=list)
    unresolved_clause_ids: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Implement conservative clause pairing and fact extraction**

Pair clauses first by exact normalized `(label, ancestor_path, heading)`, then by unique fingerprint. Never pair a tie. Compare paired text, hierarchy position, entity multisets, protected-region fingerprints, and document-feature `(kind, stable details)` groups. Emit removed and added facts for unpaired unique clauses and record tied clauses in `unresolved_clause_ids`. Generate every fact ID from a canonical JSON tuple of fact kind, stable location, and before/after fingerprints.

```python
def _fact_id(kind: str, location: str, before: str, after: str) -> str:
    raw = json.dumps([kind, location, before, after], ensure_ascii=False, separators=(",", ":")).encode()
    return f"fact-{hashlib.sha256(raw).hexdigest()[:24]}"
```

- [ ] **Step 5: Run fact tests with reordered and duplicated clauses**

Run: `python -m pytest tests/unit/verification/test_facts.py -q`

Expected: PASS; reorder is `moved`, exact replacement is `modified`, duplicates are unresolved, and repeated runs have identical IDs.

- [ ] **Step 6: Commit neutral contract facts**

```bash
git add src/artifactdiff/verification tests/unit/verification
git commit -m "feat: derive contract change facts"
```

---

### Task 4: Contract-safe rule engine and stable raw verdict

**Files:**
- Create: `src/artifactdiff/verification/rules.py`
- Create: `src/artifactdiff/verification/visual_rules.py`
- Create: `tests/unit/verification/test_rules.py`
- Create: `tests/unit/verification/test_visual_rules.py`
- Modify: `src/artifactdiff/verification/models.py`

**Interfaces:**
- Consumes: `FrozenPolicy`, baseline/candidate Contract IR, `ContractChangeSet`, `VisualPageChange`
- Produces: `FindingOutcome`, `FindingEvidence`, `Finding`, `RawVerdict`
- Produces: `evaluate_contract(policy: FrozenPolicy, baseline: ContractDocument, candidate: ContractDocument, facts: ContractChangeSet, visual_changes: list[VisualPageChange], visual_available: bool) -> RawVerdict`

- [ ] **Step 1: Write the flagship pass/review/fail tests**

```python
def test_exact_declared_30_to_45_day_edit_passes() -> None:
    verdict = evaluate_fixture(before_days=30, after_days=45, expected_after="45 天")
    assert verdict.outcome is FindingOutcome.PASS
    assert all(finding.outcome is FindingOutcome.PASS for finding in verdict.findings)


def test_extra_edit_in_allowed_payment_clause_reviews() -> None:
    verdict = evaluate_fixture(before_days=30, after_days=45, extra_payment_sentence="No late fee.", allow_payment=True)
    assert verdict.outcome is FindingOutcome.REVIEW


def test_party_change_outside_expected_span_fails() -> None:
    verdict = evaluate_fixture(before_days=30, after_days=45, party="Different Ltd.")
    assert verdict.outcome is FindingOutcome.FAIL
    assert any(item.rule_id == "contract-safe.protected.parties" for item in verdict.findings)
```

- [ ] **Step 2: Run rule tests and verify missing evaluator**

Run: `python -m pytest tests/unit/verification/test_rules.py -q`

Expected: FAIL because verdict types and evaluation do not exist.

- [ ] **Step 3: Implement stable finding and verdict models**

```python
class FindingOutcome(StrEnum):
    PASS = "pass"
    REVIEW = "review"
    FAIL = "fail"


class FindingEvidence(StrictModel):
    before_fingerprint: str | None = None
    after_fingerprint: str | None = None
    before_excerpt: str | None = None
    after_excerpt: str | None = None
    locations: list[EvidenceRef] = Field(default_factory=list)


class Finding(StrictModel):
    id: str
    rule_id: str
    rule_version: Literal["1.0"] = "1.0"
    outcome: FindingOutcome
    location: str
    selector_status: SelectorResolutionStatus | None = None
    evidence: FindingEvidence
    remediation: str
    approvable: bool = False


class RawVerdict(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    outcome: FindingOutcome
    policy_sha256: str
    baseline_sha256: str
    candidate_sha256: str
    findings: list[Finding]
```

Finding IDs are `finding-` plus the first 24 hex characters of SHA-256 over canonical `[rule_id, rule_version, location, before_fingerprint, after_fingerprint]`.

- [ ] **Step 4: Implement rule precedence and exact-replace accounting**

Evaluate in this exact order:

1. baseline and policy integrity;
2. selector resolution;
3. required exact operations;
4. protected entities and regions outside authorized replacement spans;
5. comment, tracked-revision, hidden-text, external-link, and metadata feature changes;
6. unexplained clause changes;
7. visual availability and visual changes.

For each exact operation, require the declared `before` occurrence count in the baseline clause and the same number of `after` occurrences in the candidate. Reconstruct the expected candidate clause with bounded `str.replace(before, after, occurrences)` and compare normalized text. A mismatch produces fail unless the remaining delta is inside an explicit `allow` rule, in which case it produces approvable review. Missing, duplicated, ambiguous, or changed expected operations fail and are not approvable.

```python
def _combine(findings: list[Finding]) -> FindingOutcome:
    outcomes = {finding.outcome for finding in findings}
    if FindingOutcome.FAIL in outcomes:
        return FindingOutcome.FAIL
    if FindingOutcome.REVIEW in outcomes:
        return FindingOutcome.REVIEW
    return FindingOutcome.PASS
```

- [ ] **Step 5: Implement protected and unspecified-change rules**

Mark only entity changes whose source spans are wholly inside an exact authorized replacement as explained. Party, money, currency, date, duration, percentage, header, footer, signature, seal, attachment, clause deletion, page deletion, and unresolved pairing outside those spans fail. Comment, tracked-revision, hidden-text, external-link, and embedded-image changes review unless their evidence intersects protected content, in which case they fail. Non-business metadata changes follow `metadata.non_business_change`, defaulting to review; `ignore` is an explicit signed-policy relaxation. Additional change inside an `allow` selector reviews and is approvable. Every other body change fails.

- [ ] **Step 6: Implement visual policy tests and rules**

```python
def test_visual_delta_inside_expected_bbox_passes() -> None:
    finding = assess_visual_change(expected_box=Rect(x0=10, y0=10, x1=80, y1=30), changed=Rect(x0=8, y0=9, x1=82, y1=31), padding=6)
    assert finding.outcome is FindingOutcome.PASS


def test_pagination_reflow_reviews_and_protected_region_fails() -> None:
    assert assess_pagination_reflow(policy=VisualPolicy()).outcome is FindingOutcome.REVIEW
    assert assess_protected_region_change(policy=VisualPolicy()).outcome is FindingOutcome.FAIL
```

An explained region is the union of before/after rendered evidence boxes expanded by exactly `layout_envelope_padding_points`. A changed region outside that envelope reviews. A changed page count or cascading line wrap reviews. A protected-region overlap fails. Missing visual evidence follows `on_unavailable` and never silently passes.

- [ ] **Step 7: Run the rule suite**

Run: `python -m pytest tests/unit/verification -q`

Expected: PASS for exact edits and deterministic fail/review behavior across every rule class.

- [ ] **Step 8: Commit the contract-safe rule engine**

```bash
git add src/artifactdiff/verification tests/unit/verification
git commit -m "feat: evaluate contract-safe verdicts"
```

---

### Task 5: Cross-format verification service and raw JSON artifact

**Files:**
- Create: `src/artifactdiff/visual_service.py`
- Create: `src/artifactdiff/verification/service.py`
- Create: `src/artifactdiff/verification/reporting.py`
- Create: `tests/integration/verification/test_service.py`
- Create: `tests/integration/verification/test_format_paths.py`
- Modify: `src/artifactdiff/service.py`
- Modify: `tests/integration/test_service_orchestration.py`

**Interfaces:**
- Consumes: `load_contract`, `diff_contracts`, `evaluate_contract`, existing `compare_images`
- Produces: `VisualComparison(visual_changes, assets, warnings)`
- Produces: `compare_visual_pages(before: DocumentSnapshot, after: DocumentSnapshot, output_dir: Path, *, pixel_threshold: int, tile_size: int, include_unpaired: bool = False) -> VisualComparison`
- Produces: `VerificationOptions(visual: bool = True, pixel_threshold: int = 16, tile_size: int = 32)`
- Produces: `VerificationRun(result: RawVerdict, facts: ContractChangeSet, comparison: ComparisonResult, json_path: Path, visual_assets: dict[str, VisualAssets])`
- Produces: `verify_contract_change(baseline: Path, candidate: Path, frozen_policy: FrozenPolicy, output_dir: Path, *, options: VerificationOptions) -> VerificationRun`
- Produces: `write_verification_run(verdict: RawVerdict, facts: ContractChangeSet, visual: VisualComparison, output_dir: Path) -> VerificationRun`
- Produces constant: `SUPPORTED_VERIFICATION_PAIRS = {(".docx", ".docx"), (".pdf", ".pdf"), (".docx", ".pdf")}`

- [ ] **Step 1: Extract visual-page orchestration without changing legacy results**

Move the page alignment, image comparison, warning, asset-copy, and weighted-ratio logic from `_compare_snapshots` into `compare_visual_pages`. With `include_unpaired=False`, preserve legacy behavior and skip one-sided page pairs. With `include_unpaired=True`, emit a `VisualPageChange` with the missing side set to `None` and ratio `1.0`, so contract rules can fail page deletion and review/fail page insertion according to policy. Keep `_compare_snapshots` as the legacy semantic orchestrator that calls the new function with `include_unpaired=False`. Snapshot tests must show identical `ComparisonResult` JSON before and after the refactor.

```python
@dataclass(frozen=True, slots=True)
class VisualComparison:
    visual_changes: list[VisualPageChange]
    assets: dict[str, VisualAssets]
    warnings: list[str]
    changed_pixel_ratio: float
```

- [ ] **Step 2: Run legacy orchestration tests**

Run: `python -m pytest tests/integration/test_service_orchestration.py tests/integration/test_service_weighting.py tests/integration/test_service_visual_degradation.py -q`

Expected: PASS with no report-schema or status change.

- [ ] **Step 3: Write failing three-format-path service tests**

```python
@pytest.mark.parametrize("baseline_format,candidate_format", [("docx", "docx"), ("pdf", "pdf"), ("docx", "pdf")])
def test_flagship_edit_passes_all_supported_paths(tmp_path: Path, baseline_format: str, candidate_format: str) -> None:
    baseline, candidate, frozen = contract_edit_fixture(tmp_path, baseline_format, candidate_format, 30, 45)
    run = verify_contract_change(baseline, candidate, frozen, tmp_path / "out", options=VerificationOptions(visual=False))
    assert run.result.outcome is FindingOutcome.PASS
    assert json.loads(run.json_path.read_text(encoding="utf-8"))["raw_verdict"]["outcome"] == "pass"
```

- [ ] **Step 4: Implement independent adapter loading and verification orchestration**

Validate the baseline hash before parsing the candidate. Load each input through its own adapter, allowing only `(docx, docx)`, `(pdf, pdf)`, and `(docx, pdf)`. Build both Contract IR objects, neutral facts, visual facts, and the raw verdict. Write one atomic `verification.json` containing schema version, frozen-policy digest, source descriptors, neutral facts, comparison facts, raw verdict, environment manifest, and warnings.

```python
def verify_contract_change(
    baseline: Path,
    candidate: Path,
    frozen_policy: FrozenPolicy,
    output_dir: Path,
    *,
    options: VerificationOptions,
) -> VerificationRun:
    checked_baseline = validate_source(baseline, force=False)
    checked_candidate = validate_source(candidate, force=False)
    if frozen_policy.policy.baseline.sha256 != sha256_file(checked_baseline):
        raise PolicyValidationError("baseline hash does not match frozen policy")
    if (checked_baseline.suffix.casefold(), checked_candidate.suffix.casefold()) not in SUPPORTED_VERIFICATION_PAIRS:
        raise InputValidationError("supported verification paths are DOCX-to-DOCX, PDF-to-PDF, and DOCX-to-PDF")
    with TemporaryDirectory(prefix="artifactdiff-verify-") as temporary:
        workdir = Path(temporary)
        baseline_snapshot, baseline_contract = load_contract(checked_baseline, render=options.visual, force=False, workdir=workdir / "baseline")
        candidate_snapshot, candidate_contract = load_contract(checked_candidate, render=options.visual, force=False, workdir=workdir / "candidate")
        visual = compare_visual_pages(baseline_snapshot, candidate_snapshot, workdir / "visual", pixel_threshold=options.pixel_threshold, tile_size=options.tile_size, include_unpaired=True)
        facts = diff_contracts(baseline_contract, candidate_contract)
        verdict = evaluate_contract(frozen_policy, baseline_contract, candidate_contract, facts, visual.visual_changes, not visual.warnings)
        return write_verification_run(verdict, facts, visual, output_dir)
```

- [ ] **Step 5: Test failure cleanup and deterministic bytes**

Run verification twice into different output roots and assert identical `verification.json` after replacing presentation-only absolute artifact paths with relative names. Inject an atomic rename failure and assert the temporary file is removed and no completed marker is present.

Run: `python -m pytest tests/integration/verification tests/integration/test_service_orchestration.py -q`

Expected: PASS for all supported pairs, cleanup, cross-format exact edit, ambiguity, protected change, and deterministic output.

- [ ] **Step 6: Run the full suite and commit**

Run: `python -m pytest -q`

Expected: all tests PASS.

```bash
git add src/artifactdiff/service.py src/artifactdiff/visual_service.py src/artifactdiff/verification tests/integration/verification tests/integration/test_service_orchestration.py
git commit -m "feat: verify constrained contract edits"
```

---

## Plan 2 completion gate

- [ ] YAML, JSON, and Python policies canonicalize to identical bytes.
- [ ] Policy freezing rejects baseline mismatch and non-unique selectors.
- [ ] Exact 30-to-45-day edits pass across all supported format paths.
- [ ] Extra allowed-clause edits review; out-of-scope and protected edits fail.
- [ ] Comments, revisions, hidden text, links, and metadata follow explicit contract-safe rules.
- [ ] Missing visual evidence reviews by default.
- [ ] Every finding ID and raw-verdict byte is stable on repeat execution.
- [ ] Legacy compare behavior and its complete test suite remain unchanged.
