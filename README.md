# ArtifactDiff

**A contract change verification gate for humans and AI agents.**

Prove that an AI agent changed only the Office/PDF contract terms you authorized —
semantically, visually, and cryptographically — before the document is delivered.

ArtifactDiff is local-first and offline. It turns a requested edit such as “change the
payment window from 30 days to 45 days” into a frozen policy, verifies the candidate,
and writes an immutable Review Bundle that both humans and agents can inspect.

> Project status: `0.1.0` alpha. The contract-safe core and signed Golden Path are
> implemented and covered by more than 900 automated tests. Packaging and public release
> automation are still in progress.

## What it catches

| Candidate | Verdict | Delivery gate |
| --- | --- | --- |
| Only the exact authorized clause occurrence changed | **PASS** | May proceed |
| The edit is semantically allowed but has an unexplained layout change | **REVIEW** | Blocked until a human approves that finding |
| A party, amount, date, signature, seal, attachment, or other protected content changed | **FAIL** | Blocked and not approvable |

ArtifactDiff is deliberately fail-closed. **Review remains blocking by default** and a
FAIL finding cannot be approved away.

## Three-minute Golden Path

Prerequisites: Python 3.11+ and a local checkout of this repository. The demo uses only
synthetic contracts and makes no network request after dependencies are installed.

```console
python -m venv .venv
# Activate .venv using your shell, then:
python -m pip install -e ".[dev]"
python scripts/run_contract_golden_path.py --output build/contract-golden-path
python -m json.tool build/contract-golden-path/summary.json
```

The run creates three independently verified, Ed25519-signed Review Bundles:

```text
authorized    raw=pass    effective=pass
review        raw=review  effective=review
unauthorized  raw=fail    effective=fail
```

The `review` case stays blocked. To demonstrate the signed event-chain transition with
an explicitly simulated synthetic human reviewer, use a different output directory:

```console
python scripts/run_contract_golden_path.py --output build/contract-golden-path-approved --approve-review
```

`--approve-review` is demo-only. Real approvals remain interactive human actions through
`artifactdiff review` or `artifactdiff approve`; agents cannot approve their own
findings. See the [Golden Path walkthrough](examples/contract-golden-path/README.md) for
the generated files and privacy boundaries.

## The workflow

```text
Human instruction
      │
      ▼
contract-safe policy ── freeze + optional Ed25519 authorization
      │
      ▼
controlled agent edit session
      │
      ▼
semantic rules + protected entities + visual envelope
      │
      ├── PASS ───────────────────────────────► deliver
      ├── REVIEW ─► signed per-finding review ─► deliver or reject
      └── FAIL ───────────────────────────────► reject
                          │
                          ▼
                 immutable Review Bundle
```

The Review Bundle is the system of record. The local review desk is only an authenticated
loopback interface over that bundle.

## Human and automation interfaces

The same application boundary powers every interface:

- **CLI:** create/validate/seal policies, open controlled sessions, verify changes,
  inspect findings, approve findings, and verify or pack bundles.
- **Local review desk:** inspect a bundle and sign one finding at a time without sending
  contracts or private keys to browser JavaScript.
- **MCP:** bounded inspect/draft/validate/local-verify tools for AI agents, with separate
  input and output roots and no approval or verified-signing capability.
- **Offline HTML:** portable human review reports linked to verified facts.

```console
artifactdiff --help
artifactdiff policy --help
artifactdiff verify --help
artifactdiff review path/to/review-bundle
```

For an MCP host, configure absolute, path-separator-delimited roots before starting the
stdio server:

```text
ARTIFACTDIFF_MCP_INPUT_ROOTS=/absolute/contracts
ARTIFACTDIFF_MCP_OUTPUT_ROOTS=/absolute/artifactdiff-output
artifactdiff-mcp
```

MCP intentionally cannot approve findings or perform verified signing.

## Why this is not another PDF diff

| Ordinary document diff | ArtifactDiff |
| --- | --- |
| Shows everything that changed | Proves whether changes match a pre-authorized instruction |
| Text or pixels are the final result | Semantic, protected-entity, occurrence, metadata, and visual rules combine into one gate |
| A screenshot/report is the evidence | Content-addressed Review Bundle with policy, facts, verdict, evidence, signatures, and append-only decisions |
| Designed only for a person looking at two files | CLI, Python, MCP, offline report, and human review desk share one truth model |
| “Looks fine” may pass | REVIEW and unavailable evidence block by default |

## Security and privacy model

- Local-first and offline; no account or cloud service is required.
- `contract-safe` is enabled by default, with no implicit authorization.
- Exact expected edits are bound to their clause and occurrence.
- Parties, money, currencies, dates, durations, percentages, headers, footers,
  signatures, seals, and attachments are protected by default.
- Offline Ed25519 is the core trust mechanism; enterprise identity can be added through
  adapters later.
- Evidence defaults to `minimal`; `full` is explicit and `sealed` is encrypted for named
  recipients.
- MCP responses are bounded and do not return full contracts, page images, or key
  material.

Read the approved [verification-gate design](docs/superpowers/specs/2026-08-04-artifactdiff-contract-verification-gate-design.md)
and the [Plan 4.5 acceptance record](docs/plan-4.5-contract-golden-path.md) for the full
trust and verdict model.

## Current format support

- PDF → PDF
- DOCX → DOCX
- DOCX → PDF
- English, Chinese, and bilingual contract structure
- Optional DOCX rendering through LibreOffice; PDF rendering is local

## Development

```console
python -m pip install -e ".[dev]"
python -m pytest -q
```

The repository currently contains unit, integration, tamper, CLI, MCP, review-desk,
cross-format, and signed Golden Path acceptance coverage.

## Next milestones

- Reproducible public synthetic corpus and zero-false-pass gate
- GitHub Action for binary-document pull request review
- Demo media and downloadable example Review Bundle
- Schemas, threat model, SBOM, provenance, and signed alpha release
- Plugin boundaries for enterprise parsers, renderers, signing, encryption, and storage

ArtifactDiff is being built around one narrow promise: **when an agent edits a contract,
you can prove exactly what it was allowed to change — and that it changed nothing else.**
