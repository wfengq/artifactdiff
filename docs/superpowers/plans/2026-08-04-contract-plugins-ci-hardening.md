# Contract Plugins, CI, and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make parsers and enterprise capabilities safely extensible, harden hostile-document and process boundaries, and provide a first-party GitHub Action that runs the same fail-closed contract gate.

**Architecture:** A versioned plugin registry loads capability providers but never delegates verdict combination. Verification snapshots inputs before parsing and applies archive/process/resource limits. The GitHub adapter invokes the public CLI, emits bounded summaries and annotations, and uploads minimal evidence only when explicitly configured by the workflow.

**Tech Stack:** Python 3.11-3.13, importlib.metadata entry points, packaging version/specifier utilities, existing ArtifactDiff services, PyYAML, GitHub composite actions and official GitHub workflow actions, pytest.

## Global Constraints

- This plan depends on `2026-08-04-contract-interfaces-review-desk.md` being complete.
- Plugins may supply facts, parsing, rendering, signing, encryption, storage, and CI integration; they cannot replace `contract-safe` or verdict-combination rules.
- Every used plugin identity/version/capability is recorded in the Review Bundle.
- An unapproved plugin cannot produce a verified pass.
- Verified execution uses separate resolved input/output roots and read-only input snapshots.
- Limits cover file size, PDF pages, DOCX entries, expanded ZIP size, and compression ratio.
- LibreOffice runs without a shell, with an isolated profile/work directory and timeout.
- Operational failure never leaves output that can be mistaken for a valid bundle.
- GitHub integration never approves findings and does not upload full/sealed evidence by default.

---

### Task 1: Versioned plugin contracts and deterministic discovery

**Files:**
- Create: `src/artifactdiff/plugins/__init__.py`
- Create: `src/artifactdiff/plugins/models.py`
- Create: `src/artifactdiff/plugins/protocols.py`
- Create: `src/artifactdiff/plugins/registry.py`
- Create: `tests/unit/plugins/test_models.py`
- Create: `tests/unit/plugins/test_registry.py`
- Create: `tests/integration/plugins/test_policy_allowlist.py`
- Modify: `pyproject.toml`
- Modify: `src/artifactdiff/policy/models.py`
- Modify: `src/artifactdiff/bundle/models.py`

**Interfaces:**
- Produces entry-point groups: `artifactdiff.parsers`, `artifactdiff.renderers`, `artifactdiff.ocr`, `artifactdiff.signature_providers`, `artifactdiff.encryption_providers`, `artifactdiff.ci_adapters`, `artifactdiff.evidence_stores`
- Produces: `PluginCapability`, `PluginManifest`, `LoadedPlugin`, `PluginFact`
- Produces protocols: `ParserPlugin`, `RendererPlugin`, `OcrPlugin`, `SignatureProviderPlugin`, `EncryptionProviderPlugin`, `CiAdapterPlugin`, `EvidenceStorePlugin`
- Produces: `PluginRegistry.discover() -> PluginRegistry`
- Produces: `PluginRegistry.require(constraints: Mapping[str, PolicyPluginRequirement], *, verified: bool) -> tuple[LoadedPlugin, ...]`

- [ ] **Step 1: Add `packaging` and write failing manifest tests**

Add `"packaging>=24,<27"` to runtime dependencies.

```python
def test_plugin_manifest_requires_security_disclosures() -> None:
    manifest = PluginManifest(
        api_version="1.0", name="docling", version="2.0.0", distribution="artifactdiff-docling",
        capabilities={PluginCapability.PARSER}, deterministic=True, network_use=False,
        model_use=False, license="MIT",
    )
    assert manifest.network_use is False
    assert manifest.model_use is False


def test_unknown_plugin_capability_is_rejected() -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(valid_manifest_dict(capabilities=["verdict_engine"]))
```

- [ ] **Step 2: Implement strict plugin and fact models**

```python
class PluginCapability(StrEnum):
    PARSER = "parser"
    RENDERER = "renderer"
    OCR = "ocr"
    SIGNATURE_PROVIDER = "signature_provider"
    ENCRYPTION_PROVIDER = "encryption_provider"
    CI_ADAPTER = "ci_adapter"
    EVIDENCE_STORE = "evidence_store"


class PluginManifest(StrictModel):
    api_version: Literal["1.0"] = "1.0"
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    version: str
    distribution: str
    capabilities: frozenset[PluginCapability]
    supported_formats: frozenset[str] = frozenset()
    deterministic: bool
    network_use: bool
    model_use: bool
    license: str = Field(min_length=1, max_length=128)


class PluginFact(StrictModel):
    namespace: str = Field(pattern=r"^[a-z][a-z0-9.-]{0,127}$")
    fact_type: str
    payload: dict[str, JsonValue]
    source_plugin: str
```

There is deliberately no outcome, verdict, severity, or approval field in `PluginFact`.

- [ ] **Step 3: Write failing deterministic discovery tests**

```python
def test_registry_sorts_entry_points_and_rejects_duplicate_names(fake_entry_points: list[EntryPoint]) -> None:
    registry = PluginRegistry.discover(entry_points=fake_entry_points)
    assert [plugin.manifest.name for plugin in registry.plugins] == sorted({point.name for point in fake_entry_points})
    with pytest.raises(PluginError, match="duplicate plugin name"):
        PluginRegistry.discover(entry_points=duplicate_name_entry_points())
```

- [ ] **Step 4: Implement discovery without import-time execution of unrelated groups**

Query only the seven exact groups. Sort entry points by `(group, name, value)`. Load one requested group at a time, require each object to expose `manifest() -> PluginManifest`, verify the installed distribution name/version through `importlib.metadata`, reject duplicate names, and cache immutable `LoadedPlugin` records. Map all import exceptions to a bounded `PluginError` that names the entry point but not local paths or environment values.

- [ ] **Step 5: Enforce policy constraints for verified assurance**

Use the existing `ContractPolicy.required_plugins: dict[str, PolicyPluginRequirement]`; each requirement contains a PEP 440 `version` specifier such as `">=2,<3"`, an exact distribution, and explicit `allow_network`/`allow_model` booleans. Local assurance records warnings for unmatched optional plugins. Verified assurance requires exact plugin name, exact allowed distribution, matching version, `deterministic=True`, and policy permission for any declared network or model use; the `contract-safe` default permits neither.

```python
def _allowed_for_verified(plugin: LoadedPlugin, requirement: PolicyPluginRequirement) -> bool:
    return (
        plugin.manifest.deterministic
        and plugin.manifest.distribution == requirement.distribution
        and (not plugin.manifest.network_use or requirement.allow_network)
        and (not plugin.manifest.model_use or requirement.allow_model)
        and Version(plugin.manifest.version) in SpecifierSet(requirement.version)
    )
```

- [ ] **Step 6: Record used plugins in bundles and run tests**

Run: `python -m pytest tests/unit/plugins tests/integration/plugins -q`

Expected: PASS for deterministic ordering, duplicate rejection, version mismatch, disclosure enforcement, verified allowlists, and absence of verdict fields.

- [ ] **Step 7: Commit plugin contracts**

```bash
git add pyproject.toml src/artifactdiff/plugins src/artifactdiff/policy/models.py src/artifactdiff/bundle/models.py tests/unit/plugins tests/integration/plugins
git commit -m "feat: define bounded plugin capabilities"
```

---

### Task 2: DOCX archive limits and immutable input snapshots

**Files:**
- Create: `src/artifactdiff/archive_safety.py`
- Create: `src/artifactdiff/input_snapshot.py`
- Create: `tests/unit/test_archive_safety.py`
- Create: `tests/integration/security/test_input_snapshot.py`
- Modify: `src/artifactdiff/formats/docx.py`
- Modify: `src/artifactdiff/verification/service.py`
- Modify: `src/artifactdiff/limits.py`
- Modify: `tests/unit/test_docx_adapter.py`

**Interfaces:**
- Produces constants: `MAX_DOCX_ENTRIES = 10_000`, `MAX_DOCX_EXPANDED_BYTES = 512 * 1024 * 1024`, `MAX_DOCX_ENTRY_BYTES = 64 * 1024 * 1024`, `MAX_DOCX_COMPRESSION_RATIO = 100`
- Produces: `validate_docx_archive(path: Path, *, force: bool = False) -> None`
- Produces: `InputSnapshot(original: Path, snapshot: Path, sha256: str, size_bytes: int)`
- Produces: `snapshot_input(path: Path, *, destination: Path, path_policy: PathPolicy, force: bool = False) -> InputSnapshot`

- [ ] **Step 1: Write failing ZIP-bomb and malformed-entry tests**

```python
@pytest.mark.parametrize(
    "archive",
    [too_many_entries_docx, oversized_entry_docx, excessive_total_docx, high_ratio_docx, traversal_name_docx, encrypted_entry_docx],
)
def test_unsafe_docx_archive_is_rejected(tmp_path: Path, archive: Callable[[Path], Path]) -> None:
    with pytest.raises(ResourceLimitError):
        validate_docx_archive(archive(tmp_path / "hostile.docx"))
```

- [ ] **Step 2: Implement central-directory validation before python-docx**

Open only the central directory with `zipfile.ZipFile`. Reject encrypted flags, duplicate names, absolute/backslash/drive/traversal names, entry count over 10,000, a single expanded entry over 64 MiB, total expanded size over 512 MiB, or `file_size / max(compress_size, 1) > 100`. Legacy comparison/inspection may pass `force=True` to bypass size/count thresholds, but never path, encryption, duplicate, or structural checks. Contract verification always calls this with `force=False`. Call it before `Document(path)`.

- [ ] **Step 3: Write failing validation-time replacement tests**

```python
def test_verification_parses_the_read_only_snapshot_not_mutable_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_contract_docx(tmp_path / "input" / "contract.docx")
    snapshot = snapshot_input(source, destination=tmp_path / "run" / "inputs", path_policy=path_policy(tmp_path))
    source.write_bytes(malicious_replacement_bytes())
    assert sha256_file(snapshot.snapshot) == snapshot.sha256
    assert snapshot.snapshot.stat().st_mode & stat.S_IWUSR == 0
```

- [ ] **Step 4: Implement copy-hash-recheck snapshots**

Open the resolved source, copy to a newly created destination file with exclusive creation, fsync, hash the copy, compare original `stat` identity/size/mtime before and after copy, then make the snapshot read-only. If source identity changes during copy, delete the snapshot and raise `InputChangedError`. Verification hashes and parses only the snapshot paths and records both original display paths and snapshot digests.

- [ ] **Step 5: Run hostile-input and regression tests**

Run: `python -m pytest tests/unit/test_archive_safety.py tests/integration/security/test_input_snapshot.py tests/unit/test_docx_adapter.py tests/unit/test_limits.py -q`

Expected: PASS for all hard limits, path checks, replacement races, and valid DOCX compatibility.

- [ ] **Step 6: Commit safe input snapshots**

```bash
git add src/artifactdiff/archive_safety.py src/artifactdiff/input_snapshot.py src/artifactdiff/formats/docx.py src/artifactdiff/verification/service.py src/artifactdiff/limits.py tests/unit/test_archive_safety.py tests/integration/security/test_input_snapshot.py tests/unit/test_docx_adapter.py
git commit -m "feat: harden contract input processing"
```

---

### Task 3: Process, report, and logging hardening

**Files:**
- Create: `src/artifactdiff/redaction.py`
- Create: `src/artifactdiff/run_directory.py`
- Create: `tests/unit/test_redaction.py`
- Create: `tests/integration/security/test_run_directory.py`
- Create: `tests/integration/security/test_libreoffice_boundary.py`
- Modify: `src/artifactdiff/libreoffice.py`
- Modify: `src/artifactdiff/errors.py`
- Modify: `src/artifactdiff/reporting/html.py`
- Modify: `src/artifactdiff/reporting/contract_html.py`

**Interfaces:**
- Produces: `redact_public_error(error: BaseException) -> str`
- Produces: `RunDirectory.create(root: Path, run_digest: str) -> RunDirectory`
- Produces: `RunDirectory.complete(manifest_digest: str) -> Path`
- Produces: `RunDirectory.abort() -> None`

- [ ] **Step 1: Write failing secret-redaction tests**

```python
@pytest.mark.parametrize("secret", ["SECRET CONTRACT TERM", "correct horse battery staple", "-----BEGIN ENCRYPTED PRIVATE KEY-----"])
def test_public_errors_and_logs_redact_sensitive_values(secret: str, caplog: pytest.LogCaptureFixture) -> None:
    message = redact_public_error(RuntimeError(f"failed while processing {secret}"))
    logging.getLogger("artifactdiff").error("%s", message)
    assert secret not in message
    assert secret not in caplog.text
    assert "[redacted]" in message
```

- [ ] **Step 2: Implement structured redaction and error codes**

Domain exceptions carry a stable code and public message separately from their cause. Redaction replaces PEM blocks, passphrase/key labels, paths under input roots, and user excerpts longer than 80 characters. Ordinary logs include run ID, rule ID, finding ID, plugin identity, and error code only. Debug logging may include stack traces but still uses the redaction filter.

- [ ] **Step 3: Harden LibreOffice invocation and errors**

Preserve the argument-list, `shell=False`, isolated profile, and 120-second timeout. Copy the source snapshot into an isolated conversion input directory, set the conversion working directory explicitly, pass `stdin=subprocess.DEVNULL`, cap captured stdout/stderr to 8 KiB after completion, redact it, and delete the profile/output on every handled failure. Never include contract filenames or text in the public message.

```python
completed = subprocess.run(
    args,
    shell=False,
    cwd=workdir,
    stdin=subprocess.DEVNULL,
    capture_output=True,
    text=True,
    timeout=120,
    check=False,
)
```

- [ ] **Step 4: Implement content-addressed, completion-marked run directories**

Create `.artifactdiff-<digest>-<nonce>.tmp` under the resolved output root with exclusive creation. `complete` writes a `COMPLETE` marker last and atomically renames to `<digest>`; an existing identical completed run is reusable, while a collision with different content fails. `abort` removes only the validated staging directory. All report writers target the run directory and never arbitrary existing paths.

- [ ] **Step 5: Run process and report-security tests**

Run: `python -m pytest tests/unit/test_redaction.py tests/integration/security/test_run_directory.py tests/integration/security/test_libreoffice_boundary.py tests/unit/test_libreoffice.py tests/integration/test_html_report.py tests/integration/reporting/test_contract_html.py -q`

Expected: PASS for timeout, missing executable, output collision, cleanup, XSS, no remote assets, and secret redaction.

- [ ] **Step 6: Commit process hardening**

```bash
git add src/artifactdiff/redaction.py src/artifactdiff/run_directory.py src/artifactdiff/libreoffice.py src/artifactdiff/errors.py src/artifactdiff/reporting tests/unit/test_redaction.py tests/integration/security
git commit -m "feat: harden verification process boundaries"
```

---

### Task 4: Optional enterprise provider adapters

**Files:**
- Create: `src/artifactdiff/enterprise/__init__.py`
- Create: `src/artifactdiff/enterprise/protocols.py`
- Create: `src/artifactdiff/enterprise/service.py`
- Create: `tests/unit/enterprise/test_protocols.py`
- Create: `tests/integration/enterprise/test_attestation.py`
- Modify: `src/artifactdiff/trust/signing.py`
- Modify: `src/artifactdiff/session/service.py`
- Modify: `src/artifactdiff/bundle/verifier.py`

**Interfaces:**
- Produces: `EnterpriseAttestation`, `EnterpriseAttestationProvider`, `EnterpriseSignatureProvider`, `TrustedTimeProvider`
- Produces: `verify_enterprise_assurance(policy_digest: str, baseline_digest: str, candidate_digest: str, attestation: EnterpriseAttestation, provider: EnterpriseAttestationProvider) -> None`

- [ ] **Step 1: Write failing provider-boundary tests**

```python
def test_enterprise_provider_binds_all_canonical_digests(fake_provider: FakeAttestationProvider) -> None:
    attestation = fake_provider.attest(policy="a" * 64, baseline="b" * 64, candidate="c" * 64)
    verify_enterprise_assurance("a" * 64, "b" * 64, "c" * 64, attestation, fake_provider)
    with pytest.raises(SignatureError):
        verify_enterprise_assurance("a" * 64, "b" * 64, "d" * 64, attestation, fake_provider)
```

- [ ] **Step 2: Define provider protocols without vendor dependencies**

```python
class EnterpriseAttestationProvider(Protocol):
    def manifest(self) -> PluginManifest:
        raise NotImplementedError

    def verify(self, attestation: EnterpriseAttestation, expected_payload: bytes) -> None:
        raise NotImplementedError


class TrustedTimeProvider(Protocol):
    def verify(self, evidence: dict[str, JsonValue], signature_digest: str) -> datetime:
        raise NotImplementedError
```

Core ships only protocol adapters and a deterministic fake used by tests; OIDC, Sigstore, corporate certificate, HSM, and remote review providers are separately installed plugins.

- [ ] **Step 3: Implement enterprise assurance composition**

Canonicalize `[policy_digest, baseline_digest, candidate_digest, session_digest, manifest_digest]` with domain `ArtifactDiff-Enterprise-v1`. Require a registered allowlisted provider, verify its attestation, store the provider manifest and evidence digest in the bundle, and report assurance `enterprise`. Failure or absence falls back to no verdict rather than silently downgrading to verified/local.

- [ ] **Step 4: Test provider absence, tamper, network disclosure, and bundle replay**

Run: `python -m pytest tests/unit/enterprise tests/integration/enterprise -q`

Expected: PASS; a provider for one bundle cannot attest another, unallowlisted/networked providers are rejected by default, and no vendor package is imported by core tests.

- [ ] **Step 5: Commit enterprise extension points**

```bash
git add src/artifactdiff/enterprise src/artifactdiff/trust/signing.py src/artifactdiff/session/service.py src/artifactdiff/bundle/verifier.py tests/unit/enterprise tests/integration/enterprise
git commit -m "feat: add enterprise assurance adapters"
```

---

### Task 5: Schema compatibility and non-destructive migrations

**Files:**
- Create: `src/artifactdiff/compatibility.py`
- Create: `src/artifactdiff/migrations/__init__.py`
- Create: `tests/unit/test_compatibility.py`
- Create: `tests/integration/bundle/test_old_bundle_compatibility.py`
- Modify: `src/artifactdiff/bundle/verifier.py`
- Modify: `src/artifactdiff/bundle/models.py`

**Interfaces:**
- Produces: `SchemaSupport`, `SchemaRegistry`
- Produces: `default_schema_registry() -> SchemaRegistry`
- Produces: `required_verifier_message(schema_name: str, schema_version: str, declared_range: str | None) -> str`
- Produces: `migrate_object(source: StrictModel, *, target_version: str, destination: Path) -> Path`

- [ ] **Step 1: Write failing supported/retired-schema tests**

```python
def test_v1_bundle_is_dispatched_to_v1_verifier() -> None:
    registry = default_schema_registry()
    support = registry.require("review_bundle", "1.0")
    assert support.verifier_name == "artifactdiff.bundle.v1"


def test_unknown_old_bundle_reports_exact_verifier_without_calling_it(tmp_path: Path) -> None:
    bundle = old_bundle_fixture(tmp_path, schema_version="0.8", verifier_range=">=0.8,<0.9")
    with pytest.raises(CompatibilityError, match=r"install artifactdiff>=0\.8,<0\.9"):
        verify_review_bundle(bundle, trust_store=test_trust_store())
```

- [ ] **Step 2: Implement explicit per-schema registry**

```python
@dataclass(frozen=True, slots=True)
class SchemaSupport:
    schema_name: str
    schema_version: str
    verifier_name: str
    artifactdiff_range: str


class SchemaRegistry:
    def __init__(self, supports: Sequence[SchemaSupport]) -> None:
        self._supports = {(item.schema_name, item.schema_version): item for item in supports}

    def require(self, schema_name: str, schema_version: str) -> SchemaSupport:
        try:
            return self._supports[(schema_name, schema_version)]
        except KeyError as error:
            raise CompatibilityError(required_verifier_message(schema_name, schema_version, None)) from error
```

Register Contract IR, Policy, Finding, Comparison, Review Bundle, events, and Plugin API version `1.0` separately. Read only the bounded bootstrap fields `schema_version` and `required_verifier` before dispatching. Never dynamically install or execute a requested verifier.

- [ ] **Step 3: Implement copy-on-write migrations**

`migrate_object` looks up an explicit adjacent-version pure function, validates its output against the target Pydantic model, writes a new canonical object and digest under `destination`, and leaves source bytes untouched. No generic field-dropping migration exists. With only 1.0 registered, same-version migration writes a verified copy; unsupported targets return a compatibility error.

- [ ] **Step 4: Test corrupt-versus-unsupported distinction**

Run: `python -m pytest tests/unit/test_compatibility.py tests/integration/bundle/test_old_bundle_compatibility.py -q`

Expected: PASS; malformed 1.0 is `corrupt`, well-formed unsupported version is `unsupported`, messages contain no source data, and migration never modifies the original bundle.

- [ ] **Step 5: Commit compatibility registry**

```bash
git add src/artifactdiff/compatibility.py src/artifactdiff/migrations src/artifactdiff/bundle tests/unit/test_compatibility.py tests/integration/bundle/test_old_bundle_compatibility.py
git commit -m "feat: preserve versioned bundle verification"
```

---

### Task 6: First-party GitHub Action and bounded PR summary

**Files:**
- Create: `action.yml`
- Create: `src/artifactdiff/ci/__init__.py`
- Create: `src/artifactdiff/ci/github.py`
- Create: `tests/unit/ci/test_github_summary.py`
- Create: `tests/integration/ci/test_action_contract.py`
- Create: `examples/github-action/workflow.yml`
- Modify: `src/artifactdiff/cli.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `artifactdiff ci github BUNDLE`
- Produces action inputs: `baseline`, `candidate`, `policy`, `output`, `visual`, `upload-minimal-bundle`
- Produces action outputs: `verdict`, `assurance`, `bundle-path`, `summary-path`

- [ ] **Step 1: Write failing summary redaction and annotation tests**

```python
def test_github_summary_is_bounded_and_contains_no_contract_excerpt(tmp_path: Path, review_bundle: Path) -> None:
    summary = write_github_summary(review_bundle, tmp_path / "summary.md", max_findings=20)
    text = summary.read_text(encoding="utf-8")
    assert "SECRET CONTRACT TERM" not in text
    assert text.count("| finding-") <= 20
    assert "Raw verdict" in text and "Effective verdict" in text and "Assurance" in text
```

- [ ] **Step 2: Implement GitHub summary and annotations**

Read the verified bundle, write a Markdown summary containing source filenames without parent paths, hashes shortened to 12 characters, assurance, raw/effective verdict, counts, at most 20 finding IDs/rules/outcomes/remediation summaries, and the local artifact name. Append it to `GITHUB_STEP_SUMMARY` when defined. Emit `::error`, `::warning`, or `::notice` workflow commands with percent/newline escaping and no excerpts.

- [ ] **Step 3: Implement the composite action**

`action.yml` uses `runs.using: composite`. It installs the checked-out package, invokes `artifactdiff verify`, always invokes `artifactdiff ci github`, writes outputs through `GITHUB_OUTPUT`, and exits with the original gate code. It never calls `approve`, never accepts a signing key/passphrase input, and defaults `upload-minimal-bundle` to `false`. The example workflow uses only `actions/checkout@v4`, `actions/setup-python@v5`, this local action, and conditional `actions/upload-artifact@v4` for a minimal bundle.

- [ ] **Step 4: Validate action YAML and simulated runner behavior**

```python
def test_action_has_no_approval_or_secret_inputs() -> None:
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    encoded = json.dumps(action).lower()
    assert "approve" not in encoded
    assert "passphrase" not in encoded
    assert "private-key" not in encoded
```

Run: `python -m pytest tests/unit/ci tests/integration/ci -q`

Expected: PASS for action schema, exit preservation, summary bounds, annotation escaping, and no automatic upload/approval.

- [ ] **Step 5: Run full hardening suite and commit**

Run: `python -m pytest tests/unit/plugins tests/unit/enterprise tests/unit/ci tests/integration/plugins tests/integration/security tests/integration/enterprise tests/integration/ci -q`

Run: `python -m pytest -q`

Expected: all tests PASS.

```bash
git add action.yml examples/github-action src/artifactdiff/ci tests/unit/ci tests/integration/ci pyproject.toml src/artifactdiff/cli.py
git commit -m "feat: add fail-closed GitHub contract gate"
```

---

## Plan 5 completion gate

- [ ] Plugin discovery is deterministic and rejects duplicate/unapproved capabilities.
- [ ] No plugin can directly provide an ArtifactDiff verdict.
- [ ] Verified bundles record every used plugin and enforce allowlisted versions.
- [ ] Hostile DOCX archives and validation-time source replacement are detected.
- [ ] LibreOffice, reports, errors, and run directories preserve isolation and redaction.
- [ ] Enterprise assurance binds the same canonical digests without vendor code in core.
- [ ] Unsupported old schemas report the exact compatible verifier and migrations never overwrite audit material.
- [ ] GitHub Action preserves `0/1/2` semantics, produces a bounded PR/job summary, and never approves or uploads sensitive evidence by default.
