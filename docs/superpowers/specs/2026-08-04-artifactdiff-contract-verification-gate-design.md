# ArtifactDiff Contract Verification Gate Design

**Date:** 2026-08-04

**Status:** Approved

**Target:** ArtifactDiff 1.0

## 1. Product position

ArtifactDiff is the regression test for contracts created or edited by humans and AI
agents. It does not merely report that two documents differ. It determines whether the
observed changes were authorized before editing began, produces a deterministic
`pass`, `review`, or `fail` verdict, and preserves evidence that humans, agents, CI, and
auditors can independently verify.

The flagship workflow is a constrained contract edit, such as changing a payment term
from 30 days to 45 days while proving that no other clause, protected entity, signature
area, or unexplained layout changed.

ArtifactDiff remains local-first and deterministic. An external agent may translate a
user's natural-language request into a structured draft policy, but ArtifactDiff does
not use an LLM to reinterpret the request after the contract has been modified.

## 2. Goals

- Verify DOCX-to-DOCX, PDF-to-PDF, and DOCX-to-PDF contract changes.
- Treat Chinese, English, and bilingual Chinese-English text contracts as first-class.
- Compile all policy inputs into one canonical, deterministic policy model.
- Freeze the policy against the baseline contract before editing.
- Support local assurance and high-assurance pre-signed workflows without conflating
  them.
- Apply a conservative `contract-safe` rule profile by default.
- Separate observed document status from authorization verdict.
- Give humans a local contract review desk and agents bounded structured tools over the
  same core service.
- Preserve verification facts and approvals in a portable, append-only review bundle.
- Keep sensitive document data local and minimize evidence by default.
- Allow document parsers, renderers, identity providers, encryption providers, and CI
  integrations to evolve as plugins without replacing the core rule engine.

## 3. Non-goals for 1.0

- Scanned-PDF OCR.
- PPTX or XLSX comparison.
- Editing, merging, repairing, or accepting changes inside a contract.
- LLM-based legal interpretation or advice.
- A hosted collaboration service.
- Built-in integrations for every enterprise identity provider.
- Automatically approving a review finding on behalf of a human.

These capabilities may be added later through versioned plugins or separate product
layers. They are not prerequisites for a trustworthy contract gate.

## 4. Core terminology

- **Baseline:** the contract whose hash and structure anchor the policy.
- **Candidate:** the contract produced after the requested edit.
- **Intent:** the human request before it is converted into deterministic rules.
- **Policy:** canonical rules defining expected, allowed, protected, and visual changes.
- **Finding:** one stable, evidence-backed evaluation of a rule against an observed
  change.
- **Raw verdict:** the verdict produced only from facts and the frozen policy.
- **Effective verdict:** the raw verdict after applying valid, signed approvals for
  review findings.
- **Assurance:** the trust level of the policy and approval chain.
- **Review Bundle:** the portable system of record containing immutable verification
  facts and append-only approval events.

Document comparison status remains distinct from authorization verdict. A document can
have `status: changed` and `verdict: pass` when every change is expected and authorized.

## 5. Assurance model

ArtifactDiff exposes three assurance labels:

### 5.1 Local

The policy is canonicalized, bound to the baseline SHA-256, and frozen before editing,
but it has no signature from a trusted policy authorizer. This prevents accidental
policy drift but does not claim to resist an agent that has equivalent write access to
the policy and lock files.

### 5.2 Verified

The policy is signed before editing by a trusted Ed25519 identity with the
`policy_authorizer` role. Review approvals are also signed by identities allowed to
approve the relevant finding class. ArtifactDiff verifies that signature before it
creates the isolated editable candidate and records that transition as the first event
of a controlled edit session. A candidate introduced outside that session cannot claim
the `verified` assurance label without an enterprise attestation adapter.

Offline Ed25519 proves who authorized the exact policy and preserves event order; it
does not independently prove wall-clock time. Cryptographic proof that authorization
occurred before an external event requires optional trusted-time or enterprise
attestation evidence. The UI and reports state this boundary explicitly.

### 5.3 Enterprise

An optional provider binds the same canonical digests to an enterprise identity or
attestation system such as OIDC, Sigstore, a corporate certificate, or an HSM. These
providers supplement rather than replace the offline verification model.

Every CLI, MCP, HTML, bundle, and CI result displays the assurance label. Interfaces may
not hide or visually minimize a lower assurance level.

## 6. Architecture

The existing ArtifactDiff comparison engine remains the foundation. The contract gate
adds independent layers above it:

1. Input adapters produce the existing format-neutral document snapshot.
2. A contract analysis layer produces a Contract IR.
3. Policy entry points produce one canonical policy.
4. A sealing service binds and optionally signs that policy before editing.
5. The existing semantic and visual engine establishes comparison facts.
6. A contract rule engine evaluates facts against the frozen policy.
7. A bundle writer stores facts, evidence, signatures, and later approval events.
8. CLI, Python, MCP, the local review desk, and GitHub Actions consume the same
   application services.

Parsers establish facts. Plugins may add facts. Only the core contract rule engine
produces the final verdict.

## 7. Contract IR

`DocumentSnapshot` remains the low-level interchange type. `ContractDocument` enriches
it with contract concepts:

```text
ContractDocument
├── source descriptor and content hash
├── language profile
├── clauses and clause hierarchy
├── tables
├── protected regions
├── deterministic protected entities
├── pages and source evidence references
└── extraction warnings
```

A clause records:

- Printed label, such as `第四条`, `4.2`, or `Section 4.2`.
- Heading and ancestor heading path.
- Original text, normalized text, and fingerprint.
- Parent and child relationships.
- Source DOCX blocks or PDF page/bounding-box evidence.
- Deterministically extracted money, currency, dates, durations, percentages, and
  party-name anchors.
- Cross-format locator material.

The first-class numbering grammar recognizes common Chinese and English legal forms,
including `第一条`, `第 1 条`, `一、`, `（一）`, dotted decimal numbering, `Article`, and
`Section`. Other Unicode languages remain usable through exact text anchors but do not
receive specialized clause grammar in 1.0.

## 8. Clause selection and cross-format identity

Policies never rely on page number, list ordinal, or a transient block ID as the primary
identity. A selector combines:

- Clause label.
- Heading and ancestor path.
- Exact baseline text anchor.
- Baseline normalized fingerprint.
- Expected occurrence count.

During policy sealing the selector must resolve uniquely in the baseline. Zero matches
or multiple matches reject the seal. In the candidate, an exact or deterministic
high-confidence match is accepted. Ambiguous candidate resolution produces a review
finding; a missing expected clause or expected edit produces a fail finding.

Candidate matching is conservative and versioned. A match is `high-confidence` only
when all mandatory selector fields agree and the configured fingerprint threshold and
margin over the second-best candidate are met. The policy stores the matcher version
and thresholds; defaults are owned by the versioned `contract-safe` profile rather than
runtime heuristics.

For DOCX-to-PDF, the baseline DOCX and candidate PDF independently become Contract IR
instances. Semantic matching uses clause hierarchy and text anchors rather than page
identity. Optional LibreOffice rendering supplies visual baseline pages. Its absence
never erases semantic facts.

## 9. Policy model

The local wizard, YAML/JSON input, and MCP policy tools all produce the same strict,
versioned model. The canonical form sorts keys and sets, normalizes Unicode and paths,
and excludes generation timestamps and presentation-only fields from signed bytes.

An illustrative policy is:

```yaml
schema_version: "1"
profile: contract-safe

baseline:
  sha256: "..."
  format: docx

expect:
  - id: payment-term
    selector:
      clause: "第四条"
      heading: "付款条件"
      anchor: "发票开具后 30 天内付款"
    operation:
      type: exact_replace
      before: "30 天"
      after: "45 天"
      occurrences: 1

allow:
  - selector:
      clause: "第四条"
    kinds: [modified]

protect:
  - parties
  - money
  - dates
  - headers
  - footers
  - signatures
  - seals
  - attachments

visual:
  explained_regions: pass
  pagination_reflow: review
  protected_region_change: fail
  on_unavailable: review

evidence:
  mode: minimal
```

Policy expressions are data, not executable code. They do not support arbitrary Python,
shell, templates, callbacks, or unbounded regular expressions. The canonical policy
records the baseline digest, rule profile version, and required plugin capabilities.

## 10. The `contract-safe` profile

`contract-safe` is enabled by default and denies implicit authorization. A policy may
relax a rule explicitly before it is signed; any relaxation is visible in the canonical
policy diff.

Default behavior includes:

- Unspecified body changes fail.
- Party names, money, currency, dates, durations, and percentages fail when changed
  outside an exact expected operation.
- Clause, page, attachment, signature block, or seal-region deletion fails.
- Header, footer, contract-number, signature, seal, and attachment changes fail.
- DOCX comments, tracked revisions, hidden text, and external-link changes produce at
  least review and may fail when they affect protected content.
- Non-business metadata such as the writing application or save time produces review or
  may be explicitly ignored.
- Unexplained visual changes produce review.
- Rules use stable IDs and are fully represented in findings and documentation.

This profile detects technical deviations. It does not decide whether a legal term is
commercially reasonable or legally valid.

## 11. Verdicts and findings

Every finding records:

- Stable finding ID derived from rule ID, stable location, and before/after evidence
  fingerprints.
- Rule ID and rule-profile version.
- `pass`, `review`, or `fail` outcome.
- Contract location and selector-resolution state.
- Before and after semantic evidence.
- Associated visual evidence when available.
- Remediation guidance.
- Whether the finding type permits human approval.

Rules evaluate as follows:

- An exact expected operation occurring exactly as declared, with no unexplained
  collateral change, passes.
- A required operation that is missing, duplicated, or different fails.
- Extra changes inside an allowed clause require review.
- Changes outside allowed scope fail.
- A visual change passes as explained only when it overlaps the rendered evidence for
  an exact expected semantic operation and stays inside its declared layout envelope.
- Pagination or layout reflow caused by an authorized edit requires review.
- Unexplained visual changes require review.
- Protected-region, integrity, signature, or hash failures fail.

Review is fail-closed: it blocks delivery until resolved. A signed approval can resolve
only an approvable review finding. A fail finding requires a corrected candidate or a
new policy that is re-frozen and, for high assurance, re-signed before another edit.

CLI exit codes are:

- `0`: effective verdict is pass.
- `1`: review or fail blocks the gate.
- `2`: validation or operational error prevented a valid verdict.

## 12. Visual reasoning

Visual change is evidence, not an isolated pixel threshold verdict. ArtifactDiff links
semantic locations to page and region evidence:

- Visual change within the declared layout envelope of an exact expected semantic
  operation is explained.
- Cascading line-wrap or pagination change without semantic loss is review.
- Any additional position, font, image, or page change is review even when it occurs in
  the same clause.
- Protected-region change is fail.
- Missing visual evidence follows the policy's `on_unavailable` behavior; the default is
  review, while a policy may require visual evidence and therefore fail.

Semantic output must be cross-platform stable. Pixel output is guaranteed reproducible
only under the same renderer, version, and font manifest. Verified CI records and pins
that environment.

## 13. Signing and trust store

Offline Ed25519 is the core signature mechanism. The trust store maps public-key
fingerprints to identities, roles, validity, and revocation state. Roles include:

- `policy_authorizer`
- `finding_approver`
- `archive_signer`

Signature envelopes contain the algorithm, public-key fingerprint, identity, purpose,
canonical object digest, claimed signing time, optional trusted-time evidence, and
signature. Claimed local time alone is not treated as proof of pre-edit authorization.
Verified local mode instead relies on the trusted authorizer's signature plus the
ArtifactDiff-controlled session order. Trusted timestamp or enterprise attestation
providers may strengthen that chronology claim.

The reference key provider stores private keys as encrypted PKCS#8 files and obtains
their passphrase through an interactive signing provider rather than a command-line
argument. OS keychain, CI secret, HSM, OIDC, Sigstore, and enterprise-certificate
providers implement the same interface. Private key bytes never enter a bundle, report,
browser page, MCP response, or ordinary log.

A policy may enforce separation of duties between the policy authorizer and finding
approver. Revocation does not rewrite historical bytes; re-verification reports both
signature-at-creation validity and current trust status.

## 14. Review Bundle

The bundle is the portable system of record. Its immutable core contains:

```text
review-bundle/
├── core/
│   ├── manifest.json
│   ├── manifest.sig
│   ├── policy.json
│   ├── policy.sig
│   ├── comparison.json
│   ├── verdict.json
│   └── evidence/...
└── events/
    ├── 000001-session-opened.json
    └── 000002-approval.json
```

`manifest.json` records the digest of every core payload except itself and
`manifest.sig`, plus the baseline digest, candidate digest, policy digest, and
event-chain head at verification time. `manifest.sig` signs the canonical manifest
digest with an `archive_signer` identity and is required for verified assurance; local
assurance may omit it and therefore claims accidental corruption detection, not
resistance to a malicious local rewrite.

The core is never changed after a valid verification completes. Session and approval
records are append-only signed events. Each event binds the verification digest when
available, event sequence, finding ID when applicable, decision, reason, signer, and
previous event digest. The effective verdict is recomputed from the immutable raw
verdict and the valid event chain. Events created before verification, including
session opening, are committed by the manifest; later events descend from the chain
head committed there.

Existing events are never rewritten. A packed bundle captures a specific event-chain
head and has its own root digest and optional archive signature. A modification to the
baseline, candidate, policy, comparison, evidence, or prior event invalidates
verification. Directory immutability is enforced by ArtifactDiff's write protocol and
content addressing; cryptographic tamper evidence depends on the applicable policy,
manifest, event, and archive signatures.

## 15. Evidence privacy

Evidence has three explicit modes:

### 15.1 Minimal, the default

- Does not copy original source contracts.
- Stores hashes, necessary clause snippets, and cropped visual regions.
- Omits unchanged content and complete page images.
- Is the default for MCP, CI, and PR workflows.

### 15.2 Full, explicit opt-in

- Stores complete before/after visual pages and the full review report.
- Does not automatically embed original source files.
- Displays a clear warning that the bundle contains substantially more contract data.

### 15.3 Sealed

- May include source contracts and full evidence.
- Packs and encrypts the archive for one or more recipients using the standard age
  format through the first-party `age-cli` provider.
- Invokes `age` with an argument list and no command shell.
- Keeps recipient private keys outside the bundle and outside agent context.
- Requires normal bundle hash and signature verification after decryption.

If `age` is unavailable, sealed packing fails with an actionable installation message;
minimal and full workflows remain available.

## 16. CLI and Python interfaces

Existing `compare` and `inspect` behavior remains compatible. Contract workflows add:

```text
artifactdiff policy create BASELINE -o POLICY
artifactdiff policy validate BASELINE POLICY
artifactdiff policy seal BASELINE POLICY [--sign IDENTITY] -o SEALED_POLICY
artifactdiff session open BASELINE --policy SIGNED_POLICY --output SESSION
artifactdiff verify BASELINE CANDIDATE --policy SEALED_POLICY [--session SESSION] --output BUNDLE
artifactdiff review BUNDLE
artifactdiff approve BUNDLE --finding ID --reason TEXT --sign IDENTITY
artifactdiff bundle verify BUNDLE
artifactdiff bundle pack BUNDLE --mode sealed --recipient PUBLIC_KEY
```

Every command supports bounded machine-readable JSON where appropriate. Human status
goes to stdout, public errors go to stderr, and expected domain failures do not display a
traceback by default.

## 17. MCP interfaces

MCP exposes bounded adapters over the same application services:

- `inspect_contract`
- `draft_contract_policy`
- `validate_contract_policy`
- `seal_local_policy`
- `verify_contract_change`
- `list_review_findings`
- `get_review_finding`
- `verify_review_bundle`

MCP intentionally does not expose finding approval or verified signing. An agent may
create a pending authorization request but cannot approve it. `seal_local_policy` and
`verify_contract_change` operate at local assurance; a signed policy requires the
controlled session and manifest-signing workflow outside MCP. Inputs and outputs must
remain within independently configured resolved input and output roots. MCP responses do
not contain full pages, full contracts, private keys, or unbounded findings.

## 18. Local contract review desk

`artifactdiff policy create` and `artifactdiff review` open a short-lived local service
bound to `127.0.0.1`. The service uses a high-entropy session token, strict CSP, CSRF
protection, Origin validation, and no remote scripts, fonts, telemetry, or network calls.

The pre-edit screen shows the original intent, human-readable policy summary, exact
baseline locations, `contract-safe` defaults, policy relaxations, canonical diff, and
assurance state before freezing or signing. In verified local mode, successful policy
verification creates a fresh isolated candidate workspace and session-opened event;
the Agent receives that workspace only after this transition.

The post-edit screen shows finding navigation, linked semantic and visual evidence, raw
and effective verdicts, approval reason, signature status, and the event chain. The
browser never receives private-key bytes. A signature provider performs authorization
and signing outside ordinary page JavaScript.

Remote binding is not a core option. A separately installed enterprise adapter is
required for authenticated remote review.

## 19. GitHub and CI integration

The GitHub Action runs the same CLI service. It posts a concise PR summary, preserves the
exit semantics, and can publish a minimal review bundle as a workflow artifact. It does
not upload full or sealed evidence by default. High-assurance CI pins the ArtifactDiff
version, renderer, LibreOffice version, plugins, and fonts and records their provenance.

The Action never performs human approval. Protected environment workflows may invoke a
separate signer after an authorized reviewer acts.

## 20. File, document, and process safety

High-assurance execution:

- Configures separate input and output allow roots.
- Resolves and rechecks paths against symbolic-link escape.
- Writes each run to a new content-addressed directory and does not overwrite arbitrary
  user files.
- Copies inputs into isolated read-only snapshots before hashing and parsing to prevent
  validation-time replacement.
- Limits file size, page count, DOCX entry count, expanded ZIP size, and compression
  ratio.
- Runs LibreOffice with an argument list, isolated profile, isolated work directory, and
  timeout.
- Escapes all untrusted report content and disallows remote report dependencies.
- Redacts contract text and key material from errors and ordinary logs.
- Removes incomplete temporary output after handled failures.

An operational failure never leaves a directory that can be mistaken for a valid review
bundle.

## 21. Plugin architecture

Versioned entry-point groups cover:

- parser
- renderer
- OCR
- signature provider
- encryption provider
- CI adapter
- evidence store

Each plugin declares its name, version, supported formats and capabilities,
determinism, network use, model use, license, and distribution identity. Bundles record
the plugins actually used. Verified policies may allowlist plugin identities and
versions. An unapproved plugin cannot produce a verified pass.

Plugins may supply structured facts, rendering, signing, encryption, or storage. They
cannot replace `contract-safe` evaluation or the core verdict-combination rules.

Docling, OfficeCLI, OCR, cloud identity, and enterprise storage are candidate optional
plugins rather than mandatory core dependencies.

## 22. Testing and quality gates

The public golden corpus uses redistributable synthetic contracts and covers Chinese,
English, and bilingual documents across all three supported format paths. It includes
exact edits, additional in-scope edits, out-of-scope edits, protected entities, tables,
headers, footers, signatures, seals, attachments, metadata, visual reflow, ambiguity,
hidden content, tracked changes, malformed files, and hostile payloads.

Release quality gates include:

- No false pass in the golden and adversarial corpus.
- Every exact expected fixture passes.
- Every out-of-scope semantic fixture fails.
- Ambiguous location never passes.
- Protected-region change never passes.
- Canonical policy bytes, semantic findings, finding IDs, and bundle digests are stable
  for the same inputs and environment.
- Tampering with any signed or hashed component is detected.
- MCP output remains bounded and privacy-preserving.
- A failed run cannot be mistaken for a completed bundle.

Tests include unit, property, format-fixture, cross-format, signature-vector, tamper,
event-chain, plugin-contract, CLI, MCP in-memory session, browser end-to-end, malformed
document, path-safety, and CI integration suites.

The matrix covers Python 3.11 through 3.13 on Windows, macOS, and Linux, with and without
LibreOffice. Pixel-golden tests run in a pinned Linux renderer/font environment; other
platforms validate semantic stability, behavior, and documented visual tolerance.

## 23. Schema and compatibility

Contract IR, Policy, Finding, Comparison, Review Bundle, and Plugin API are independently
versioned. ArtifactDiff preserves the ability to verify old bundles. When an old bundle
requires a retired verifier, the tool reports the exact compatible verifier rather than
calling the bundle corrupt.

Schema migrations create new objects and new digests; they never overwrite original
audit material. Breaking schema changes follow semantic versioning.

## 24. ArtifactDiff 1.0 acceptance criteria

1. A user can install ArtifactDiff from PyPI and complete the flagship 30-to-45-day
   contract edit tutorial without a network service or account.
2. DOCX-to-DOCX, PDF-to-PDF, and DOCX-to-PDF work for Chinese, English, and bilingual
   text contracts.
3. Policy wizard, YAML/JSON, and MCP produce the same canonical policy model.
4. `contract-safe` is active by default and every relaxation is visible before signing.
5. Local and verified workflows are distinguishable and independently testable.
6. Offline Ed25519 policy and review-approval signatures verify correctly.
7. Raw and effective verdicts follow the specified pass, review, and fail rules.
8. Minimal, full, and sealed evidence modes work and enforce their privacy boundaries.
9. The local review desk can inspect and sign individual review approvals without
   exposing private keys to page JavaScript.
10. CLI, Python API, MCP, and GitHub Action consume the same core services.
11. Review bundles survive copying and independently detect tampering.
12. The test matrix and zero-false-pass golden-corpus gate pass.
13. Releases include a signed version tag, wheel and source distribution, SBOM, build
    provenance, threat model, rule catalog, schema documentation, demo GIF, and
    downloadable synthetic example bundle.

## 25. Migration from the current MVP

The existing comparison service, adapters, models, JSON/HTML writers, CLI, and MCP
remain working throughout development. Contract verification is added behind new
versioned services and commands. Current `compare` output stays a factual comparison;
it does not silently acquire policy semantics.

Implementation proceeds in independently reviewable layers: schema and Contract IR,
policy canonicalization, rule engine, sealing and trust, bundle core, approval events,
evidence privacy, CLI/MCP, local review desk, cross-format hardening, plugins, GitHub
Action, corpus, and release engineering. ArtifactDiff declares 1.0 only when all
acceptance criteria are met.
