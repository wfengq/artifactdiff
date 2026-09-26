# Contract Interfaces and Local Review Desk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the complete contract workflow through compatible CLI and bounded MCP interfaces, plus an offline loopback review desk for policy authoring, finding inspection, and human-signed approvals.

**Architecture:** CLI, MCP, static reports, and the local web desk are thin adapters over one application facade. MCP remains read/create/verify-only and cannot approve. The review server returns a data-free shell first, exchanges a URL-fragment token for a CSRF-bound session, and delegates all signing to a server-side interactive provider.

**Tech Stack:** Python 3.11-3.13, Typer, FastMCP, Starlette, Uvicorn, Jinja2, vanilla HTML/CSS/JavaScript, Pydantic, pytest/httpx.

## Global Constraints

- This plan depends on `2026-08-04-contract-trust-bundle.md` being complete.
- CLI, Python, MCP, local review desk, static HTML, and CI must consume the same application services.
- CLI exit `0` means effective pass, `1` means review/fail blocking, and `2` means validation or operational error.
- MCP does not expose approval or verified signing.
- MCP inputs and outputs stay inside independently configured resolved roots.
- MCP responses contain no full contracts, full pages, private keys, or unbounded findings.
- The review server binds only `127.0.0.1` and makes no remote requests.
- The browser never receives private-key bytes or passphrases.
- Review findings are approved individually with a non-empty reason and signed binding hash.
- Existing `compare`, `inspect`, `compare_documents`, and `inspect_document` interfaces remain available.

---

### Task 1: Application facade and complete CLI command tree

**Files:**
- Create: `src/artifactdiff/application.py`
- Create: `src/artifactdiff/cli_policy.py`
- Create: `src/artifactdiff/cli_session.py`
- Create: `src/artifactdiff/cli_bundle.py`
- Create: `src/artifactdiff/cli_review.py`
- Create: `tests/integration/cli/test_policy_commands.py`
- Create: `tests/integration/cli/test_verify_commands.py`
- Create: `tests/integration/cli/test_bundle_commands.py`
- Modify: `src/artifactdiff/cli.py`

**Interfaces:**
- Produces: `ArtifactDiffApplication` methods `inspect_contract`, `draft_policy`, `validate_policy`, `seal_policy`, `open_verified_session`, `verify_change`, `list_findings`, `get_finding`, `approve`, `verify_bundle`, `pack_bundle`
- Produces CLI commands: `policy create`, `policy validate`, `policy seal`, `session open`, `verify`, `review`, `approve`, `bundle verify`, `bundle pack`
- Preserves CLI commands: `compare`, `inspect`

- [ ] **Step 1: Write failing CLI discovery and exit-code tests**

```python
def test_contract_cli_commands_are_discoverable() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("compare", "inspect", "policy", "session", "verify", "review", "approve", "bundle"):
        assert command in result.stdout


def test_verify_exit_codes_follow_effective_verdict(tmp_path: Path) -> None:
    passing = invoke_verify(tmp_path, fixture="exact")
    review = invoke_verify(tmp_path, fixture="reflow")
    failing = invoke_verify(tmp_path, fixture="party-change")
    assert (passing.exit_code, review.exit_code, failing.exit_code) == (0, 1, 1)
```

- [ ] **Step 2: Run CLI tests and verify missing commands**

Run: `python -m pytest tests/integration/cli -q`

Expected: FAIL because contract command groups are absent.

- [ ] **Step 3: Implement the facade as the only interface dependency**

```python
@dataclass(frozen=True, slots=True)
class ArtifactDiffApplication:
    trust_store: TrustStore
    path_policy: PathPolicy | None = None
    manifest_signer: SigningProvider | None = None

    def inspect_contract(self, path: Path, *, max_clauses: int = 100) -> dict[str, object]:
        source = self.path_policy.resolve_input(path) if self.path_policy else path
        return inspect_contract(source, max_clauses=max_clauses)

    def verify_change(
        self,
        baseline: Path,
        candidate: Path,
        sealed_policy: Path,
        output: Path,
        options: VerificationOptions,
        session_path: Path | None = None,
    ) -> Path:
        checked_baseline = self.path_policy.resolve_input(baseline) if self.path_policy else baseline
        checked_candidate = self.path_policy.resolve_input(candidate) if self.path_policy else candidate
        checked_policy = self.path_policy.resolve_input(sealed_policy) if self.path_policy else sealed_policy
        checked_output = self.path_policy.resolve_output(output) if self.path_policy else output
        artifact = load_sealed_policy(checked_policy)
        session = load_edit_session(session_path, trust_store=self.trust_store) if session_path is not None else None
        if artifact.authorization is not None and session is None:
            raise SessionError("verified policy verification requires --session")
        if session is not None:
            checked_candidate = claim_verified_candidate(checked_candidate, session)
            if session.baseline_sha256 != sha256_file(checked_baseline):
                raise SessionError("session baseline does not match verification baseline")
        run = verify_contract_change(
            checked_baseline,
            checked_candidate,
            artifact.frozen,
            checked_output / "run",
            options=options,
        )
        return write_review_bundle(
            run,
            artifact.frozen,
            destination=checked_output,
            assurance=assurance_for(artifact, self.trust_store),
            policy_authorization=artifact.authorization,
            session_event=session.events[0] if session is not None else None,
            manifest_signer=self.manifest_signer,
        )
```

Implement the remaining named interface methods as direct calls to `draft_exact_replace_policy`, `validate_policy`, `freeze_policy`, `open_verified_edit_session`, `list_findings`, `approve_finding`, `verify_review_bundle`, and `pack_bundle`, applying the same input/output root checks before each call. The facade adds root checks, bounded result selection, and public exception translation only; it contains no parsing, policy, signature, or verdict logic.

- [ ] **Step 4: Implement policy command behavior**

`policy create BASELINE -o POLICY` accepts `--rule-id`, `--clause`, `--heading`, `--anchor`, `--before`, and `--after` for non-interactive use; when any is missing and stdin is a TTY, prompt for it exactly once. It inspects the baseline, drafts `contract-safe`, writes YAML for `.yaml/.yml` and canonical JSON for `.json`, and refuses to overwrite without `--force-output`.

`policy validate BASELINE POLICY` prints canonical policy SHA-256 and resolved clause ID. `policy seal BASELINE POLICY -o SEALED_POLICY` freezes locally; `--sign IDENTITY --key KEY --trust-store STORE` produces a verified authorization after an interactive passphrase request. No passphrase option or environment variable exists.

`session open BASELINE --policy SEALED_POLICY --output SESSION_ROOT --sign IDENTITY --key KEY --trust-store STORE` accepts only a valid signed policy artifact, invokes `open_verified_edit_session`, and prints the absolute candidate workspace path plus session ID. It creates no session for a local artifact, bad signature, wrong baseline, or non-`archive_signer` identity.

- [ ] **Step 5: Implement verify, review, approve, and bundle commands**

```python
def _exit_for_verdict(outcome: FindingOutcome) -> None:
    if outcome in {FindingOutcome.REVIEW, FindingOutcome.FAIL}:
        raise typer.Exit(1)
```

`verify` writes a Review Bundle and prints JSON only when `--json` is set. A locally frozen policy accepts the two supplied paths. A verified policy additionally requires `--session SESSION`, `--archive-sign IDENTITY`, and `--archive-key KEY`; the baseline digest must match the session and the candidate must be that session's candidate workspace, and a server-side `LocalEd25519SigningProvider` signs the completed core manifest. `review` opens the local desk in Task 3 and supports `--no-open` for tests. `approve` requires `--finding`, `--reason`, `--sign`, and `--key`; it is an explicitly human-operated CLI, requires a TTY-backed interactive signing provider, and has no non-interactive override. `bundle verify` returns `2` for malformed/tampered bundles and `1` for a valid blocking effective verdict. `bundle pack` accepts only `minimal`, `full`, or `sealed`; sealed requires one or more `--recipient` values.

- [ ] **Step 6: Verify public errors contain no traceback or contract text**

```python
def test_bad_signature_is_public_error_without_traceback(tmp_path: Path) -> None:
    result = runner.invoke(app, ["bundle", "verify", str(tampered_bundle(tmp_path))])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "SECRET CONTRACT TERM" not in result.output
```

Run: `python -m pytest tests/integration/cli tests/integration/test_cli.py -q`

Expected: PASS for discovery, formats, prompts, non-overwrite behavior, JSON purity, and all exit codes.

- [ ] **Step 7: Commit application and CLI adapters**

```bash
git add src/artifactdiff/application.py src/artifactdiff/cli.py src/artifactdiff/cli_policy.py src/artifactdiff/cli_session.py src/artifactdiff/cli_bundle.py src/artifactdiff/cli_review.py tests/integration/cli
git commit -m "feat: expose contract verification CLI"
```

---

### Task 2: Bounded MCP contract tools and root confinement

**Files:**
- Create: `src/artifactdiff/mcp_paths.py`
- Create: `tests/integration/mcp/test_contract_tools.py`
- Create: `tests/integration/mcp/test_path_roots.py`
- Modify: `src/artifactdiff/mcp_server.py`
- Modify: `tests/integration/test_mcp_server.py`

**Interfaces:**
- Produces MCP tools: `inspect_contract`, `draft_contract_policy`, `validate_contract_policy`, `seal_local_policy`, `verify_contract_change`, `list_review_findings`, `get_review_finding`, `verify_review_bundle`
- Preserves MCP tools: `compare_documents`, `inspect_document`
- Produces: `McpRoots.from_environment() -> McpRoots`

- [ ] **Step 1: Write failing MCP tool-list and approval-absence tests**

```python
async def test_mcp_exposes_bounded_contract_tools_but_no_approval() -> None:
    names = await list_tool_names(mcp)
    expected = {
        "compare_documents", "inspect_document", "inspect_contract", "draft_contract_policy",
        "validate_contract_policy", "seal_local_policy", "verify_contract_change",
        "list_review_findings", "get_review_finding", "verify_review_bundle",
    }
    assert set(names) == expected
    assert not any("approve" in name or "sign_verified" in name for name in names)
```

- [ ] **Step 2: Implement independent input/output root configuration**

Read `ARTIFACTDIFF_MCP_INPUT_ROOTS` and `ARTIFACTDIFF_MCP_OUTPUT_ROOTS` as `os.pathsep`-separated absolute paths. Empty or relative values fail server startup. Default each to an empty tuple, which disables file tools until configured; unit tests may inject roots directly. Resolve and recheck every path through `PathPolicy` before calling the application facade.

```python
@dataclass(frozen=True, slots=True)
class McpRoots:
    inputs: tuple[Path, ...]
    outputs: tuple[Path, ...]

    def path_policy(self) -> PathPolicy:
        return PathPolicy(input_roots=self.inputs, output_roots=self.outputs)
```

- [ ] **Step 3: Implement the eight thin tools**

Each tool catches only public `ArtifactDiffError` and returns `{ok: false, error_type, error}`. Policy drafting returns a canonical policy object, digest, and at most 20 selector candidates. Policy validation and local sealing never sign. MCP verification accepts only a locally sealed artifact; a signed artifact returns an actionable error requiring the controlled CLI/enterprise runner because MCP has neither session nor manifest-signing authority. Successful verification returns local assurance, raw/effective verdict, at most 20 finding summaries, truncation flags, and an absolute bundle path inside the output root.

`list_review_findings` accepts `cursor: int = 0` and `limit: int = 20` constrained to `1..100`. `get_review_finding` returns one finding with each excerpt truncated to 2,000 Unicode characters and crop paths, not image bytes. `verify_review_bundle` returns validity, assurance, trust status, effective outcome, and public error codes only.

- [ ] **Step 4: Test traversal, symlink, response bounds, and private-data exclusion**

```python
async def test_mcp_response_never_contains_sources_pages_or_key_material(configured_mcp: FastMCP) -> None:
    response = await call_tool(configured_mcp, "verify_contract_change", valid_args())
    encoded = json.dumps(response, ensure_ascii=False)
    assert "BEGIN PRIVATE KEY" not in encoded
    assert "data:image" not in encoded
    assert full_contract_text() not in encoded
    assert len(response["findings"]) <= 20
```

Run: `python -m pytest tests/integration/mcp tests/integration/test_mcp_server.py -q`

Expected: PASS; relative paths, root escape, symlink swaps, and unconfigured roots fail without creating outputs.

- [ ] **Step 5: Commit MCP adapters**

```bash
git add src/artifactdiff/mcp_paths.py src/artifactdiff/mcp_server.py tests/integration/mcp tests/integration/test_mcp_server.py
git commit -m "feat: expose bounded contract MCP tools"
```

---

### Task 3: Loopback review server security shell

**Files:**
- Create: `src/artifactdiff/review_web/__init__.py`
- Create: `src/artifactdiff/review_web/app.py`
- Create: `src/artifactdiff/review_web/server.py`
- Create: `src/artifactdiff/review_web/assets/index.html`
- Create: `src/artifactdiff/review_web/assets/app.js`
- Create: `src/artifactdiff/review_web/assets/styles.css`
- Create: `tests/unit/review_web/test_security.py`
- Create: `tests/integration/review_web/test_session.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `ReviewContext(application, mode, target_path, signing_provider)`
- Produces: `create_review_app(context: ReviewContext, session_token: str, csrf_token: str) -> Starlette`
- Produces: `serve_review(context: ReviewContext, *, open_browser: bool = True) -> ReviewServer`
- Routes: `GET /`, `GET /assets/app.js`, `GET /assets/styles.css`, `POST /api/session`, `GET /api/policy`, `POST /api/policy`, `POST /api/policy/seal`, `GET /api/bundle`, `GET /api/findings`, `GET /api/findings/{id}`, `POST /api/approvals`, `POST /api/shutdown`

- [ ] **Step 1: Add explicit web dependencies and failing security-header tests**

Add runtime dependencies `"starlette>=0.37,<1"` and `"uvicorn>=0.30,<1"`; add dev dependency `"httpx>=0.27,<1"`. Include all three static assets in the wheel.

```python
def test_shell_contains_no_sensitive_data_and_sets_strict_headers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "SECRET CONTRACT TERM" not in response.text
    assert response.headers["content-security-policy"] == "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
```

- [ ] **Step 2: Implement the data-free shell and middleware**

Serve only packaged local files. Add CSP, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `Cross-Origin-Resource-Policy: same-origin` to every response. Reject `Host` values other than the exact bound loopback host/port. Uvicorn access logs are disabled.

- [ ] **Step 3: Implement fragment-token exchange and CSRF checks**

The server prints and opens `http://127.0.0.1:<port>/#token=<43-character-base64url-token>`; fragments never reach HTTP logs. `app.js` reads the fragment, immediately calls `history.replaceState` to remove it, and sends it only in `X-ArtifactDiff-Session` on `POST /api/session`. The response returns the CSRF token in JSON. All later API calls require both session and CSRF headers. Every mutating request additionally requires exact `Origin: http://127.0.0.1:<port>` and `Content-Type: application/json`.

```javascript
const token = new URLSearchParams(location.hash.slice(1)).get("token");
history.replaceState(null, "", location.pathname);
const session = await fetch("/api/session", {method: "POST", headers: {"X-ArtifactDiff-Session": token}}).then(r => r.json());
```

- [ ] **Step 4: Test token, origin, CSRF, remote-bind, and shutdown behavior**

Run: `python -m pytest tests/unit/review_web/test_security.py tests/integration/review_web/test_session.py -q`

Expected: PASS; API data is inaccessible without both tokens, cross-origin POST returns 403, reused shutdown token fails, the server binds only IPv4 loopback, and idle shutdown leaves no process.

- [ ] **Step 5: Commit the secure review shell**

```bash
git add pyproject.toml src/artifactdiff/review_web tests/unit/review_web tests/integration/review_web
git commit -m "feat: serve secure local review shell"
```

---

### Task 4: Policy wizard and finding review desk

**Files:**
- Create: `src/artifactdiff/review_web/views.py`
- Create: `src/artifactdiff/review_web/signing_provider.py`
- Create: `tests/integration/review_web/test_policy_wizard.py`
- Create: `tests/integration/review_web/test_finding_review.py`
- Modify: `src/artifactdiff/review_web/app.py`
- Modify: `src/artifactdiff/review_web/assets/index.html`
- Modify: `src/artifactdiff/review_web/assets/app.js`
- Modify: `src/artifactdiff/review_web/assets/styles.css`
- Modify: `src/artifactdiff/cli_policy.py`
- Modify: `src/artifactdiff/cli_review.py`

**Interfaces:**
- Produces: `ReviewSigningProvider.sign_policy(frozen: FrozenPolicy) -> PolicyAuthorization`
- Produces: `ReviewSigningProvider.sign_approval(bundle: Path, finding_id: str, reason: str) -> ApprovalEvent`
- Produces: `InteractiveEd25519SigningProvider`
- Produces UI states: `policy-draft`, `policy-ready`, `bundle-pass`, `bundle-review`, `bundle-fail`, `approval-pending`, `approval-complete`

- [ ] **Step 1: Write failing wizard-equivalence test**

```python
def test_wizard_and_yaml_create_same_canonical_policy(review_client: ReviewClient, baseline: Path) -> None:
    response = review_client.post_json("/api/policy", payment_wizard_payload())
    wizard_policy = ContractPolicy.model_validate(response["policy"])
    yaml_policy = load_policy(write_payment_yaml(baseline))
    assert canonical_policy_bytes(wizard_policy) == canonical_policy_bytes(yaml_policy)
```

- [ ] **Step 2: Implement pre-edit policy view and explicit relaxations**

Show intent, baseline hash/format, selected clause path, exact before/after values and counts, protected defaults, metadata behavior, visual rules, evidence mode, required plugins, canonical digest, and assurance. Any change to `protect`, metadata behavior, visual behavior, or evidence mode appears in a dedicated `Relaxations from contract-safe` list before freeze/sign. The server revalidates all submitted selectors and values; the browser is not trusted. In final behavior, interactive `artifactdiff policy create` opens this wizard by default, while `--no-open` uses the terminal fallback from Task 1. `POST /api/policy/seal` freezes locally or invokes the server-side signing provider for verified assurance and returns only the sealed public artifact.

- [ ] **Step 3: Write failing finding navigation and signed approval tests**

```python
def test_review_desk_approves_one_finding_and_updates_effective_verdict(review_client: ReviewClient, review_bundle: Path) -> None:
    finding = review_client.get_json("/api/findings?cursor=0&limit=20")["items"][0]
    result = review_client.post_json("/api/approvals", {"finding_id": finding["id"], "reason": "Layout reflow reviewed against the signed instruction"})
    assert result["event"]["finding_id"] == finding["id"]
    assert result["effective_verdict"]["outcome"] == "pass"
```

- [ ] **Step 4: Implement review rendering and server-side signing**

The desk displays assurance prominently, raw and effective verdicts, a finding list, semantic before/after excerpts, page crops, selector state, rule/remediation, signature/trust status, and event history. It never returns full source contracts. Approval is enabled only for `review && approvable`; fail findings display no approval control.

`InteractiveEd25519SigningProvider` implements both high-level review operations over the generic digest signer. It obtains the passphrase with `getpass.getpass` on the server side, converts it to a scoped byte buffer for key loading, calls `authorize_policy` or `approve_finding`, overwrites that mutable buffer in `finally`, and does not retain either the original string or decoded private key. Documentation states that Python cannot guarantee erasure of immutable string/runtime copies; high-assurance deployments should prefer OS keychain or HSM providers. A `FakeSigningProvider` supports tests. JavaScript receives only the signed public authorization or event.

- [ ] **Step 5: Implement accessible, offline interactions**

Use semantic buttons, labels, focus management, `aria-live` for verdict changes, keyboard previous/next finding actions, and CSS that remains usable from 320px to 1440px. Assets contain no remote URL, font, analytics, dynamic code execution, or HTML insertion from untrusted strings; render text through `textContent`.

- [ ] **Step 6: Run wizard, review, and static-asset tests**

Run: `python -m pytest tests/integration/review_web -q`

Expected: PASS for canonical equivalence, XSS strings, review pagination, approval, fail refusal, key non-exposure, and all view states.

- [ ] **Step 7: Commit the local contract review desk**

```bash
git add src/artifactdiff/review_web src/artifactdiff/cli_policy.py src/artifactdiff/cli_review.py tests/integration/review_web
git commit -m "feat: add local contract review desk"
```

---

### Task 5: Portable offline contract report

**Files:**
- Create: `src/artifactdiff/reporting/contract_html.py`
- Create: `src/artifactdiff/reporting/contract_template.html`
- Create: `tests/integration/reporting/test_contract_html.py`
- Modify: `src/artifactdiff/bundle/writer.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `write_contract_html(bundle: Path, output: Path, *, trust_store: TrustStore) -> Path`

- [ ] **Step 1: Write failing self-contained report tests**

```python
def test_contract_report_is_offline_escaped_and_assurance_visible(tmp_path: Path, review_bundle: Path) -> None:
    report = write_contract_html(review_bundle, tmp_path / "review.html", trust_store=test_trust_store())
    html = report.read_text(encoding="utf-8")
    assert "VERIFIED" in html
    assert "Raw verdict" in html and "Effective verdict" in html
    assert "https://" not in html and "http://" not in html
    assert "<script>alert(1)</script>" not in html
```

- [ ] **Step 2: Implement strict offline report rendering**

Use a strict Jinja environment with autoescape. Embed only evidence already authorized by the bundle's mode as Base64 data URLs. Render source digests, policy summary, relaxations, findings, semantic excerpts, available crops/pages, raw/effective verdict, assurance, signatures, trust-at-creation/current-trust status, and approval event history. The report is read-only and contains no signing or approval function.

The output parent is an explicit trust boundary: it must be a private directory controlled by the current user. Write a hidden staging file in that directory, flush and verify it completely, then atomically hard-link it to a must-be-new final name. This guarantee is portable across Windows, macOS, and Linux; mutation by another same-privilege writer with access to that trusted directory is outside the contract.

- [ ] **Step 3: Test deterministic HTML and partial evidence**

Run: `python -m pytest tests/integration/reporting/test_contract_html.py tests/integration/test_html_report.py -q`

Expected: PASS; same bundle produces identical HTML, minimal mode omits full pages, unavailable visuals show a review warning, and legacy HTML remains unchanged.

- [ ] **Step 4: Run complete interface suite and commit**

Run: `python -m pytest tests/integration/cli tests/integration/mcp tests/integration/review_web tests/integration/reporting tests/integration/test_cli.py tests/integration/test_mcp_server.py tests/integration/test_html_report.py -q`

Run: `python -m pytest -q`

Expected: all tests PASS.

```bash
git add pyproject.toml src/artifactdiff/reporting src/artifactdiff/bundle/writer.py tests/integration/reporting
git commit -m "feat: render offline contract review reports"
```

---

## Plan 4 completion gate

- [ ] A user can draft, validate, freeze/sign, verify, review, approve, verify, and pack through CLI.
- [ ] CLI exit codes are exactly `0` pass, `1` blocking verdict, and `2` operational error.
- [ ] All eight bounded contract MCP tools work and no approval/signing tool exists.
- [ ] MCP file access cannot escape configured input/output roots.
- [ ] Local review uses a fragment token, CSRF token, exact Origin, strict CSP, and loopback binding.
- [ ] Policy wizard, YAML/JSON, Python, and MCP produce identical canonical policy bytes.
- [ ] Approval signing happens server-side and exposes no private key or passphrase to JavaScript.
- [ ] Static contract reports are escaped, deterministic, self-contained, and read-only.
