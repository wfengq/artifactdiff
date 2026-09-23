# ArtifactDiff

ArtifactDiff 是一个本地运行的合同修改核验原型。用户先指定允许修改的条款，
系统再检查候选 DOCX 或带文字层的 PDF，给出 `PASS`、`REVIEW` 或 `FAIL`，
并保存可校验的审查记录。目前已有合成合同端到端演示；真实合同适配仍在验证，
扫描件和部分多栏、复杂版式尚未可靠支持。

ArtifactDiff checks whether a contract edit made by a person or an AI agent matches a
policy that was approved before editing. It combines semantic rules, protected values,
occurrence checks, and visual evidence. The result is stored in a content-addressed
Review Bundle that can be checked later for unexpected modification.

> Project status: `0.1.0` alpha. The signed synthetic Golden Path is implemented, and
> the repository has more than 900 automated tests. Packaging, broader real-contract
> evaluation, and public release automation remain in progress.

## Verdicts

| Candidate | Verdict | Delivery decision |
| --- | --- | --- |
| The expected clause occurrence changed, and the required evidence is available | **PASS** | May proceed under the configured policy |
| The edit appears allowed, but visual evidence is missing or contains an unexplained change | **REVIEW** | Blocked until a human reviews the finding |
| A protected value changed outside the authorization, or an expected edit is missing | **FAIL** | Blocked and not approvable |

ArtifactDiff fails closed. `REVIEW` blocks delivery by default, and a `FAIL` finding
cannot be approved away. A `PASS` is a software verdict under the configured policy.
It is not legal approval of a contract.

## Run the synthetic Golden Path

You need Python 3.11 or later and a local checkout. The demo generates synthetic
contracts and makes no network request after the dependencies are installed.

```console
python -m venv .venv
# Activate .venv using your shell, then run:
python -m pip install -e ".[dev]"
python scripts/run_contract_golden_path.py --output build/contract-golden-path
python -m json.tool build/contract-golden-path/summary.json
```

The command writes three Ed25519-signed Review Bundles and verifies them from disk:

```text
authorized    raw=pass    effective=pass
review        raw=review  effective=review
unauthorized  raw=fail    effective=fail
```

The `review` case stays blocked. To demonstrate a signed decision from a simulated
human reviewer, use a separate output directory:

```console
python scripts/run_contract_golden_path.py --output build/contract-golden-path-approved --approve-review
```

`--approve-review` exists only for the synthetic demo. In normal use, a person approves
a finding through `artifactdiff review` or `artifactdiff approve`. An agent cannot
approve its own finding. The [Golden Path walkthrough](examples/contract-golden-path/README.md)
describes the generated files and privacy boundaries.

## Verification flow

```text
Human instruction
      |
      v
contract-safe policy: freeze and optional Ed25519 authorization
      |
      v
controlled edit session
      |
      v
semantic rules, protected values, and visual evidence
      |
      +-- PASS ------------------------------------> deliver
      +-- REVIEW --> signed human decision --------> deliver or reject
      +-- FAIL ------------------------------------> reject
                              |
                              v
              content-addressed Review Bundle
```

The Review Bundle is the stored record. It includes the policy, comparison facts,
verdict, evidence index, and signed events when verified assurance is enabled. The
verifier recomputes file digests and signature claims from the bundle bytes.

## Interfaces

The interfaces use the same verdict and evidence data:

- **CLI:** create, validate, and seal policies; run verification; inspect findings;
  record human decisions; and verify or pack bundles.
- **Local review desk:** inspect a bundle and sign one finding at a time. Contract files
  and private keys are not sent to browser JavaScript.
- **MCP:** inspect, draft, validate, and run local verification from bounded input and
  output roots. MCP cannot approve findings or perform verified signing.
- **Offline HTML:** create a portable report linked to the recorded facts.

```console
artifactdiff --help
artifactdiff policy --help
artifactdiff verify --help
artifactdiff review path/to/review-bundle
```

For an MCP host, configure absolute input and output roots before starting the stdio
server. Separate multiple roots with the platform path separator.

```text
ARTIFACTDIFF_MCP_INPUT_ROOTS=/absolute/contracts
ARTIFACTDIFF_MCP_OUTPUT_ROOTS=/absolute/artifactdiff-output
artifactdiff-mcp
```

## How this differs from a plain document diff

| Plain document diff | ArtifactDiff |
| --- | --- |
| Lists changed text or pixels | Checks changes against a policy created before editing |
| Leaves every change for a person to interpret | Separates allowed edits, protected-value changes, and unavailable evidence |
| Produces a report or screenshot | Writes a content-addressed bundle with facts, evidence, verdicts, and optional signatures |
| Usually has one human-facing interface | Uses the same data through the CLI, Python API, MCP server, HTML report, and review desk |
| May treat missing evidence as no visible change | Returns a blocking verdict when required evidence is unavailable |

## Security and privacy model

- The default workflow runs locally and does not require an account or cloud service.
- `contract-safe` is enabled by default and grants no implicit authorization.
- Expected edits bind to a clause, an occurrence, and the text before and after the edit.
- Recognized parties, money, currencies, dates, durations, percentages, headers,
  footers, signatures, seals, and attachments are protected by default.
- Ed25519 signatures provide the implemented offline trust mechanism. Enterprise
  identity support is not implemented.
- Evidence defaults to `minimal`. `full` is explicit, and `sealed` encrypts evidence for
  named recipients.
- MCP responses are bounded and do not return full contracts, page images, or key
  material.

Read the [verification-gate design](docs/superpowers/specs/2026-08-04-artifactdiff-contract-verification-gate-design.md)
and the [Golden Path acceptance record](docs/plan-4.5-contract-golden-path.md) for the
trust and verdict model.

## Supported inputs and current limits

The implemented paths cover:

- DOCX compared with DOCX.
- Text-based PDF compared with text-based PDF.
- DOCX compared with a rendered PDF when LibreOffice rendering is configured.
- Selected English, Chinese, and bilingual contract examples.

The current limits are material:

- ArtifactDiff does not perform OCR. A scanned PDF without extractable text produces a
  warning and cannot receive the same text verification as a text-based PDF.
- Multi-column PDFs, tables, and unusual reading orders can produce incorrect text
  grouping. These layouts require human review and more evaluation.
- Protected-value extraction uses deterministic patterns. It is not a legal named-entity
  model and does not claim to recognize every contract term.
- The end-to-end Golden Path uses synthetic contracts. Tests on selected external
  documents do not establish production accuracy or a zero-false-pass rate.
- ArtifactDiff is an engineering prototype, not a substitute for legal review.

## Development

```console
python -m pip install -e ".[dev]"
python -m pytest -q
```

The test suite includes unit, integration, tamper, CLI, MCP, review-desk, cross-format,
and signed Golden Path coverage.

## Planned work

- Publish a reproducible synthetic corpus and a measured false-pass gate.
- Add a GitHub Action for binary-document pull request review.
- Publish demo media and an example Review Bundle.
- Publish schemas, a threat model, an SBOM, provenance, and a signed alpha release.
- Define adapter boundaries for enterprise parsers, renderers, signing, encryption, and
  storage.

The project has one narrow goal: make an agent's permitted contract edit and the
evidence for its verdict inspectable before delivery.
