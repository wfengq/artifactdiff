# Contract Trust and Review Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add offline Ed25519 authorization, controlled verified edit sessions, immutable Review Bundle cores, signed append-only approval events, and minimal/full/sealed evidence handling.

**Architecture:** Trust, session, bundle, approval, and evidence code live in separate focused packages. Signatures bind canonical digests with purpose-specific domain separation. Verified editing begins only after policy authorization is checked; verification writes a new bundle atomically; later approvals append signed events and recompute rather than rewrite the effective verdict.

**Tech Stack:** Python 3.11-3.13, Pydantic 2, cryptography Ed25519/PKCS#8, SHA-256, standard-library tarfile/subprocess, external `age` CLI for sealed archives, pytest.

## Global Constraints

- This plan depends on `2026-08-04-contract-policy-verdict.md` being complete.
- Offline Ed25519 is the core signature mechanism.
- Local assurance must never be displayed as verified assurance.
- Verified mode checks signed policy authorization before creating the Agent's editable candidate workspace.
- Offline signatures prove identity, content, and event order; they do not independently prove wall-clock time.
- Private-key bytes never enter a bundle, browser page, MCP response, report, or ordinary log.
- Review blocks by default; only an approvable review finding can be human-approved.
- Fail findings cannot be approved.
- Bundle core files are immutable after completion; approval events append and hash-chain.
- Minimal evidence is default, full is explicit, and sealed uses the standard age format.

---

### Task 1: Ed25519 keys, signature envelopes, and trust store

**Files:**
- Create: `src/artifactdiff/trust/__init__.py`
- Create: `src/artifactdiff/trust/models.py`
- Create: `src/artifactdiff/trust/keys.py`
- Create: `src/artifactdiff/trust/signing.py`
- Create: `src/artifactdiff/trust/store.py`
- Create: `tests/unit/trust/test_keys.py`
- Create: `tests/unit/trust/test_signing.py`
- Create: `tests/unit/trust/test_store.py`
- Modify: `pyproject.toml`
- Modify: `src/artifactdiff/errors.py`

**Interfaces:**
- Produces: `TrustRole`, `TrustIdentity`, `TrustStore`, `SignatureEnvelope`, `PolicyAuthorization`
- Produces: `SecretProvider.get_secret(identity: str) -> bytes`
- Produces: `SigningProvider.sign(*, purpose: str, digest: str, required_role: TrustRole) -> SignatureEnvelope`
- Produces: `LocalEd25519SigningProvider`
- Produces: `generate_private_key(path: Path, *, identity: str, secret_provider: SecretProvider) -> str`
- Produces: `load_private_key(path: Path, *, identity: str, secret_provider: SecretProvider) -> Ed25519PrivateKey`
- Produces: `sign_digest(private_key: Ed25519PrivateKey, *, identity: TrustIdentity, purpose: str, digest: str, claimed_time: datetime | None = None, trusted_time: dict[str, JsonValue] | None = None) -> SignatureEnvelope`
- Produces: `verify_signature(envelope: SignatureEnvelope, *, purpose: str, digest: str, required_role: TrustRole, trust_store: TrustStore) -> TrustIdentity`

- [ ] **Step 1: Add cryptography and write failing key-storage tests**

Add `"cryptography>=44,<47"` to runtime dependencies.

```python
class FixedSecretProvider:
    def get_secret(self, identity: str) -> bytes:
        assert identity == "alice"
        return b"correct horse battery staple"


def test_private_key_is_encrypted_pkcs8(tmp_path: Path) -> None:
    path = tmp_path / "alice.pem"
    fingerprint = generate_private_key(path, identity="alice", secret_provider=FixedSecretProvider())
    raw = path.read_bytes()
    assert raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert b"PRIVATE KEY-----\nMC4CAQ" not in raw
    assert len(fingerprint) == 64
```

- [ ] **Step 2: Run trust tests and verify missing-package failure**

Run: `python -m pytest tests/unit/trust/test_keys.py -q`

Expected: FAIL because `artifactdiff.trust` does not exist.

- [ ] **Step 3: Implement strict trust models**

```python
class TrustRole(StrEnum):
    POLICY_AUTHORIZER = "policy_authorizer"
    FINDING_APPROVER = "finding_approver"
    ARCHIVE_SIGNER = "archive_signer"


class TrustIdentity(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    subject_type: Literal["human", "service", "agent"]
    public_key_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key_pem: str
    roles: frozenset[TrustRole]
    revoked: bool = False
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class TrustStore(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    identities: list[TrustIdentity]


class SignatureEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_fingerprint: str
    identity: str
    purpose: str
    canonical_object_sha256: str
    claimed_signing_time: datetime | None = None
    trusted_time_evidence: dict[str, JsonValue] | None = None
    signature_base64: str


class PolicyAuthorization(StrictModel):
    frozen_policy_sha256: str
    signature: SignatureEnvelope


class SigningProvider(Protocol):
    def sign(self, *, purpose: str, digest: str, required_role: TrustRole) -> SignatureEnvelope:
        raise NotImplementedError
```

`LocalEd25519SigningProvider` owns the identity, encrypted-key path, secret provider, and trust-store lookup. It loads the key only inside `sign`, verifies that the identity has `required_role`, calls `sign_digest`, and releases all key references before returning the public envelope. Session, bundle, approval, and archive services depend on this protocol rather than accepting raw private keys.

- [ ] **Step 4: Implement encrypted PKCS#8 generation and loading**

Use `Ed25519PrivateKey.generate()`, `Encoding.PEM`, `PrivateFormat.PKCS8`, and `BestAvailableEncryption(secret)`. Write with mode `0o600` where supported through an adjacent file and atomic replace. Compute the public-key fingerprint over DER SubjectPublicKeyInfo bytes. Reject empty secrets and map wrong-passphrase/invalid-key errors to `SignatureError` without echoing secrets or raw key content.

```python
private_bytes = key.private_bytes(
    Encoding.PEM,
    PrivateFormat.PKCS8,
    BestAvailableEncryption(secret),
)
public_der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
fingerprint = hashlib.sha256(public_der).hexdigest()
```

- [ ] **Step 5: Write failing signature-purpose and trust tests**

```python
def test_signature_is_bound_to_purpose_and_digest(key_pair: KeyPair, trust_store: TrustStore) -> None:
    envelope = sign_digest(key_pair.private, identity=key_pair.identity, purpose="policy", digest="a" * 64)
    assert verify_signature(envelope, purpose="policy", digest="a" * 64, required_role=TrustRole.POLICY_AUTHORIZER, trust_store=trust_store) == key_pair.identity
    with pytest.raises(SignatureError):
        verify_signature(envelope, purpose="approval", digest="a" * 64, required_role=TrustRole.FINDING_APPROVER, trust_store=trust_store)


def test_revoked_identity_reports_historical_and_current_status(key_pair: KeyPair, revoked_store: TrustStore) -> None:
    envelope = sign_digest(key_pair.private, identity=key_pair.identity, purpose="policy", digest="a" * 64)
    result = inspect_signature(envelope, purpose="policy", digest="a" * 64, trust_store=revoked_store)
    assert result.signature_valid is True
    assert result.currently_trusted is False
```

- [ ] **Step 6: Implement domain-separated signing and verification**

Sign exactly `b"ArtifactDiff-Signature-v1\0" + purpose.encode("ascii") + b"\0" + bytes.fromhex(digest)`. Verification requires matching purpose, digest, identity, fingerprint, Ed25519 algorithm, public key, and role. `claimed_signing_time` is informational unless `trusted_time_evidence` is verified by a separately registered adapter.

```python
def _signature_message(purpose: str, digest: str) -> bytes:
    if not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", purpose):
        raise SignatureError("invalid signature purpose")
    return b"ArtifactDiff-Signature-v1\0" + purpose.encode("ascii") + b"\0" + bytes.fromhex(digest)
```

- [ ] **Step 7: Run signature vectors and commit**

Run: `python -m pytest tests/unit/trust -q`

Expected: PASS for RFC 8032-derived fixed vectors, encryption, wrong passphrase, role mismatch, revocation reporting, digest tamper, and purpose substitution.

```bash
git add pyproject.toml src/artifactdiff/errors.py src/artifactdiff/trust tests/unit/trust
git commit -m "feat: add offline Ed25519 trust"
```

---

### Task 2: Verified policy authorization and controlled edit sessions

**Files:**
- Create: `src/artifactdiff/session/__init__.py`
- Create: `src/artifactdiff/session/models.py`
- Create: `src/artifactdiff/session/service.py`
- Create: `src/artifactdiff/fs_safety.py`
- Create: `tests/unit/test_fs_safety.py`
- Create: `tests/integration/session/test_verified_session.py`
- Modify: `src/artifactdiff/policy/service.py`

**Interfaces:**
- Produces: `PathPolicy(input_roots: tuple[Path, ...], output_roots: tuple[Path, ...])`
- Produces: `authorize_policy(frozen: FrozenPolicy, *, signer: SigningProvider) -> PolicyAuthorization`
- Produces: `SessionOpenedEvent`, `EditSession`
- Produces: `SealedPolicyArtifact(frozen: FrozenPolicy, authorization: PolicyAuthorization | None)`
- Produces: `write_sealed_policy(artifact: SealedPolicyArtifact, path: Path) -> Path`
- Produces: `load_sealed_policy(path: Path) -> SealedPolicyArtifact`
- Produces: `open_verified_edit_session(baseline: Path, frozen: FrozenPolicy, authorization: PolicyAuthorization, *, root: Path, trust_store: TrustStore, session_signer: SigningProvider, path_policy: PathPolicy) -> EditSession`
- Produces: `load_edit_session(path: Path, *, trust_store: TrustStore) -> EditSession`
- Produces: `claim_verified_candidate(candidate: Path, session: EditSession) -> Path`

- [ ] **Step 1: Write failing path-containment tests**

```python
def test_path_policy_rejects_symlink_escape(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir(); outside.mkdir()
    link = allowed / "escape"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(PathSafetyError):
        PathPolicy(input_roots=(allowed,), output_roots=(allowed,)).resolve_input(link / "contract.docx")


def test_output_must_be_under_a_separate_output_root(tmp_path: Path) -> None:
    policy = PathPolicy(input_roots=(tmp_path / "in",), output_roots=(tmp_path / "out",))
    with pytest.raises(PathSafetyError):
        policy.resolve_output(tmp_path / "in" / "result")
```

- [ ] **Step 2: Implement resolve-and-recheck path policy**

Resolve each root once at construction. For every path, require `candidate == root or root in candidate.parents`, reject any unresolved link component, create output parents one level at a time, then resolve and recheck after creation. Input and output root sets must be disjoint.

- [ ] **Step 3: Write failing verified-session tests**

```python
def test_verified_session_is_created_only_after_policy_signature_verifies(session_fixture: SessionFixture) -> None:
    session = open_verified_edit_session(**session_fixture.valid_args())
    assert session.assurance == "verified"
    assert session.candidate_path.read_bytes() == session_fixture.baseline.read_bytes()
    assert session.baseline_snapshot_path.stat().st_mode & stat.S_IWUSR == 0
    assert session.events[0].event_type == "session_opened"


def test_invalid_policy_signature_creates_no_workspace(session_fixture: SessionFixture) -> None:
    with pytest.raises(SignatureError):
        open_verified_edit_session(**session_fixture.tampered_args())
    assert list(session_fixture.root.iterdir()) == []
```

- [ ] **Step 4: Implement authorization and fresh session creation**

`authorize_policy` signs the frozen policy canonical digest with purpose `policy_authorization`. Session opening verifies that signature and role, verifies the baseline hash, creates a staging directory under the resolved output root, copies the baseline to `baseline/<name>`, copies it again to `candidate/<name>`, makes only the baseline snapshot read-only, writes canonical `session.json` and `events/000001-session-opened.json` signed by an `archive_signer` provider, then atomically renames staging to `sessions/<session_id>`.

`SealedPolicyArtifact` stores the immutable frozen policy plus an optional authorization envelope in one strict canonical JSON file. Its assurance is derived when loaded: absent authorization is `local`; a valid authorization from a trusted `policy_authorizer` is `verified`; serialized input cannot set the assurance label directly.

Compute `session_id` from the policy digest, baseline digest, and a 32-byte `secrets.token_bytes` nonce. The event records the nonce digest, not the nonce. It carries the policy authorization digest and explicitly records `chronology: "artifactdiff_controlled_session"` and `trusted_time: false` unless trusted-time evidence exists.

- [ ] **Step 5: Test crash cleanup and outside-session refusal**

Inject failures after each file write and assert no final session directory exists. Pass an already edited external candidate to `claim_verified_candidate` and assert it raises `SessionError("verified candidates must originate in an ArtifactDiff edit session")`.

Run: `python -m pytest tests/unit/test_fs_safety.py tests/integration/session -q`

Expected: PASS for valid, invalid-signature, wrong-baseline, symlink, crash-cleanup, and trusted-time-label cases.

- [ ] **Step 6: Commit controlled verified sessions**

```bash
git add src/artifactdiff/fs_safety.py src/artifactdiff/session src/artifactdiff/policy/service.py tests/unit/test_fs_safety.py tests/integration/session
git commit -m "feat: open verified contract edit sessions"
```

---

### Task 3: Immutable Review Bundle core and independent verification

**Files:**
- Create: `src/artifactdiff/bundle/__init__.py`
- Create: `src/artifactdiff/bundle/models.py`
- Create: `src/artifactdiff/bundle/digests.py`
- Create: `src/artifactdiff/bundle/writer.py`
- Create: `src/artifactdiff/bundle/verifier.py`
- Create: `tests/unit/bundle/test_digests.py`
- Create: `tests/integration/bundle/test_writer.py`
- Create: `tests/integration/bundle/test_tamper.py`
- Modify: `src/artifactdiff/verification/service.py`

**Interfaces:**
- Produces: `BundleAssurance`, `BundlePayload`, `BundleManifest`, `BundleVerification`
- Produces: `write_review_bundle(run: VerificationRun, frozen: FrozenPolicy, *, destination: Path, assurance: BundleAssurance, policy_authorization: PolicyAuthorization | None, session_event: SessionOpenedEvent | None, manifest_signer: SigningProvider | None) -> Path`
- Produces: `verify_review_bundle(path: Path, *, trust_store: TrustStore) -> BundleVerification`
- Produces: `canonical_file_digest(path: Path) -> str`

- [ ] **Step 1: Write failing manifest and no-self-reference tests**

```python
def test_manifest_hashes_payloads_but_not_itself_or_signature(bundle_fixture: BundleFixture) -> None:
    manifest = bundle_fixture.manifest
    assert "policy.json" in {item.path for item in manifest.payloads}
    assert "manifest.json" not in {item.path for item in manifest.payloads}
    assert "manifest.sig" not in {item.path for item in manifest.payloads}


def test_verified_bundle_requires_archive_signature(bundle_fixture: BundleFixture) -> None:
    with pytest.raises(BundleError, match="manifest signature"):
        write_review_bundle(**bundle_fixture.verified_args(manifest_signer=None))
```

- [ ] **Step 2: Implement portable bundle models and canonical path rules**

```python
class BundleAssurance(StrEnum):
    LOCAL = "local"
    VERIFIED = "verified"
    ENTERPRISE = "enterprise"


class BundlePayload(StrictModel):
    path: str
    sha256: str
    size_bytes: int


class BundleManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    assurance: BundleAssurance
    baseline_sha256: str
    candidate_sha256: str
    policy_sha256: str
    raw_verdict_sha256: str
    event_chain_head: str | None = None
    payloads: list[BundlePayload]
    environment: dict[str, str]


class BundleVerification(StrictModel):
    valid: bool
    assurance: BundleAssurance
    signature_valid_at_creation: bool | None
    currently_trusted: bool | None
    event_chain_valid: bool
    errors: list[str] = Field(default_factory=list)
```

Bundle paths are relative POSIX paths, NFC-normalized, unique, sorted, and may not be absolute or contain `.`/`..` segments, backslashes, NUL, drive letters, or names outside `core/` and `events/`.

- [ ] **Step 3: Implement atomic bundle writing**

Write only to a fresh staging directory. Core payloads are `policy.json`, optional `policy.sig`, `comparison.json`, `facts.json`, `verdict.json`, `evidence/index.json`, and environment data. Hash each payload, write canonical `manifest.json`, and for verified assurance sign its digest with purpose `bundle_manifest` and an `archive_signer`. Copy the signed session event as the first event. Create `COMPLETE` last with the manifest digest, fsync files where supported, then rename staging to a content-addressed directory. Never overwrite an existing completed directory unless its manifest digest is identical.

```python
def _payload(path: Path, relative: str) -> BundlePayload:
    return BundlePayload(path=relative, sha256=sha256_file(path), size_bytes=path.stat().st_size)
```

- [ ] **Step 4: Implement independent verification and tamper tests**

Verification reads `COMPLETE`, validates all paths before opening them, validates schema and canonical manifest bytes, recomputes every payload hash, verifies policy authorization and manifest signatures for verified bundles, verifies source digests, and verifies the event chain. It collects public error codes without leaking contract excerpts.

```python
@pytest.mark.parametrize("target", ["policy.json", "comparison.json", "verdict.json", "evidence/index.json", "events/000001-session-opened.json"])
def test_any_payload_tamper_is_detected(bundle_path: Path, target: str) -> None:
    mutate_one_byte(bundle_path / ("core/" + target if "/" not in target else target))
    result = verify_review_bundle(bundle_path, trust_store=test_trust_store())
    assert result.valid is False
```

- [ ] **Step 5: Test local-versus-verified claims**

Assert a local bundle without `manifest.sig` verifies internal hashes but reports `signature_valid_at_creation=None` and `assurance="local"`. Assert renaming its manifest to `verified` fails. Assert a verified bundle with a recomputed malicious manifest but no valid signature fails.

Run: `python -m pytest tests/unit/bundle tests/integration/bundle -q`

Expected: PASS for atomic creation, collision behavior, signature roles, and every tamper target.

- [ ] **Step 6: Commit immutable bundle core**

```bash
git add src/artifactdiff/bundle src/artifactdiff/verification/service.py tests/unit/bundle tests/integration/bundle
git commit -m "feat: write immutable review bundles"
```

---

### Task 4: Append-only approval events and effective verdict

**Files:**
- Create: `src/artifactdiff/bundle/events.py`
- Create: `src/artifactdiff/review/__init__.py`
- Create: `src/artifactdiff/review/models.py`
- Create: `src/artifactdiff/review/service.py`
- Create: `tests/unit/review/test_effective_verdict.py`
- Create: `tests/integration/review/test_approval_chain.py`
- Modify: `src/artifactdiff/bundle/verifier.py`

**Interfaces:**
- Produces: `ApprovalDecision`, `ApprovalEvent`, `EffectiveVerdict`
- Produces: `list_findings(bundle: Path) -> list[Finding]`
- Produces: `approve_finding(bundle: Path, finding_id: str, reason: str, *, signer: SigningProvider, trust_store: TrustStore) -> ApprovalEvent`
- Produces: `compute_effective_verdict(raw: RawVerdict, events: Sequence[ApprovalEvent], *, trust_store: TrustStore, verification_digest: str) -> EffectiveVerdict`

- [ ] **Step 1: Write failing fail-closed approval tests**

```python
def test_approving_each_review_finding_changes_effective_verdict_to_pass(review_bundle: Path) -> None:
    for finding in list_findings(review_bundle):
        if finding.outcome == "review":
            approve_finding(review_bundle, finding.id, "Reviewed against signed instruction", **human_signer())
    effective = load_effective_verdict(review_bundle, trust_store=test_trust_store())
    assert effective.outcome == "pass"


def test_fail_finding_cannot_be_approved(fail_bundle: Path) -> None:
    finding = next(item for item in list_findings(fail_bundle) if item.outcome == "fail")
    with pytest.raises(ApprovalError, match="fail findings cannot be approved"):
        approve_finding(fail_bundle, finding.id, "Accept anyway", **human_signer())
```

- [ ] **Step 2: Implement approval and effective-verdict models**

```python
class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_type: Literal["finding_decision"] = "finding_decision"
    sequence: int = Field(ge=1)
    verification_digest: str
    previous_event_digest: str
    finding_id: str
    decision: ApprovalDecision
    reason: str = Field(min_length=3, max_length=2000)
    signature: SignatureEnvelope


class EffectiveVerdict(StrictModel):
    raw_outcome: FindingOutcome
    outcome: FindingOutcome
    approved_finding_ids: list[str]
    remaining_review_finding_ids: list[str]
    fail_finding_ids: list[str]
    event_chain_head: str
```

- [ ] **Step 3: Implement locked append and hash-chain validation**

Acquire an exclusive `.events.lock` using `os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)` with a 30-second stale-lock policy based on a recorded process ID and nonce. Re-read the chain after locking. A local bundle with no session starts approval sequence `1` and uses the manifest digest as `previous_event_digest`; a verified session continues after its session-opened event. Require a `subject_type="human"` identity with the `finding_approver` role, and reject agent/service identities, unknown, non-review, non-approvable, already-decided, or wrong-verification findings. Sign the canonical unsigned event digest with purpose `finding_approval`, write `events/<sequence>-approval.json.tmp`, fsync, replace, and release the lock in `finally`.

- [ ] **Step 4: Implement effective verdict recomputation**

Validate every event sequence, previous digest, verification digest, signer role, and signature. Ignore no invalid event: any invalid chain makes bundle verification fail. `APPROVED` resolves one approvable review; `REJECTED` leaves it blocking. Any fail remains fail. Remaining review produces review; otherwise the effective outcome is pass.

```python
def _effective_outcome(raw: RawVerdict, approved: set[str]) -> FindingOutcome:
    if any(item.outcome is FindingOutcome.FAIL for item in raw.findings):
        return FindingOutcome.FAIL
    if any(item.outcome is FindingOutcome.REVIEW and item.id not in approved for item in raw.findings):
        return FindingOutcome.REVIEW
    return FindingOutcome.PASS
```

- [ ] **Step 5: Test replay, reorder, duplicate, and cross-bundle attacks**

Run: `python -m pytest tests/unit/review tests/integration/review -q`

Expected: PASS; deleting, reordering, replaying, duplicating, or copying an approval to another bundle invalidates the chain. Agent/untrusted identities cannot approve.

- [ ] **Step 6: Commit signed human approvals**

```bash
git add src/artifactdiff/bundle src/artifactdiff/review tests/unit/review tests/integration/review
git commit -m "feat: append signed finding approvals"
```

---

### Task 5: Minimal, full, and sealed evidence archives

**Files:**
- Create: `src/artifactdiff/evidence/__init__.py`
- Create: `src/artifactdiff/evidence/models.py`
- Create: `src/artifactdiff/evidence/collector.py`
- Create: `src/artifactdiff/evidence/archive.py`
- Create: `src/artifactdiff/evidence/age_cli.py`
- Create: `tests/unit/evidence/test_collector.py`
- Create: `tests/unit/evidence/test_age_cli.py`
- Create: `tests/integration/evidence/test_archive.py`
- Modify: `src/artifactdiff/bundle/writer.py`

**Interfaces:**
- Produces: `EvidenceIndex`, `EvidenceItem`, `AgeCliProvider`
- Produces: `collect_evidence(run: VerificationRun, mode: EvidenceMode, destination: Path, *, baseline: Path, candidate: Path) -> EvidenceIndex`
- Produces: `pack_bundle(bundle: Path, output: Path, *, mode: EvidenceMode, recipients: Sequence[str] = (), age_provider: AgeCliProvider | None = None, archive_signer: SigningProvider | None = None) -> Path`

- [ ] **Step 1: Write failing privacy-boundary tests**

```python
def test_minimal_evidence_omits_sources_and_full_pages(verification_run: VerificationRun, tmp_path: Path) -> None:
    index = collect_evidence(verification_run, EvidenceMode.MINIMAL, tmp_path / "evidence", baseline=baseline_path(), candidate=candidate_path())
    paths = {item.path for item in index.items}
    assert not any("source" in path or path.endswith("page.png") for path in paths)
    assert max((item.excerpt_characters for item in index.items), default=0) <= 500


def test_full_evidence_requires_explicit_mode(verification_run: VerificationRun, tmp_path: Path) -> None:
    index = collect_evidence(verification_run, EvidenceMode.FULL, tmp_path / "evidence", baseline=baseline_path(), candidate=candidate_path())
    assert any(item.kind == "full_page" for item in index.items)
    assert not any(item.kind == "source_contract" for item in index.items)
```

- [ ] **Step 2: Implement evidence collection with redaction limits**

Minimal mode stores source hashes, at most 500 Unicode characters before and after per finding, and only changed-region crops with 12-pixel context. Full mode additionally stores complete before/after rendered pages and full review HTML, but not source contracts. Sealed staging may include source contracts only when the caller passes `include_sources=True`. Every item records kind, relative path, SHA-256, byte size, finding IDs, and excerpt length.

- [ ] **Step 3: Write failing age invocation tests**

```python
def test_age_uses_argument_list_without_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], bool]] = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: calls.append((args, kwargs["shell"])) or CompletedProcess(args, 0, "", ""))
    AgeCliProvider(Path("age")).encrypt(tmp_path / "bundle.tar", tmp_path / "bundle.tar.age", ["age1example"])
    assert calls == [(["age", "-r", "age1example", "-o", str(tmp_path / "bundle.tar.age"), str(tmp_path / "bundle.tar")], False)]
```

- [ ] **Step 4: Implement deterministic tar packing and age encryption**

Create a PAX tar with entries sorted by relative path and normalized metadata: `mtime=0`, `uid=gid=0`, `uname=gname=""`, file mode `0o600`, directory mode `0o700`. Minimal/full produce `.tar`; sealed requires at least one syntactically valid age recipient and produces `.tar.age`. Invoke `age` with an argument list, `shell=False`, captured output, a 300-second timeout, and an output temporary file. If the executable is absent, raise `EncryptionUnavailableError` with the exact installation command `Install age and ensure the 'age' executable is on PATH.`

- [ ] **Step 5: Verify after decrypt and test failure cleanup**

Use a fake age executable in integration tests to round-trip bytes. After decryption, extract only through a safe member validator and call `verify_review_bundle`. Timeout, nonzero exit, missing output, path traversal, and interrupted packing must leave no completed archive.

Run: `python -m pytest tests/unit/evidence tests/integration/evidence -q`

Expected: PASS for minimal/full privacy, sealed argument safety, deterministic tar bytes, missing-age error, and decrypt-then-verify.

- [ ] **Step 6: Run all trust and bundle tests and commit**

Run: `python -m pytest tests/unit/trust tests/unit/bundle tests/unit/review tests/unit/evidence tests/integration/session tests/integration/bundle tests/integration/review tests/integration/evidence -q`

Run: `python -m pytest -q`

Expected: all tests PASS.

```bash
git add src/artifactdiff/evidence src/artifactdiff/bundle/writer.py tests/unit/evidence tests/integration/evidence
git commit -m "feat: enforce review bundle evidence privacy"
```

---

## Plan 3 completion gate

- [ ] Encrypted PKCS#8 Ed25519 keys sign and verify fixed test vectors.
- [ ] Role, revocation, purpose, digest, and claimed-time boundaries are explicit.
- [ ] Verified sessions create candidate workspaces only after policy signature validation.
- [ ] Local bundles cannot claim verified assurance.
- [ ] Any core or event mutation invalidates independent verification.
- [ ] Review approvals are finding-specific, signed, append-only, and hash-bound.
- [ ] Fail findings remain impossible to approve.
- [ ] Minimal, full, and sealed modes enforce their documented privacy boundaries.
