# ArtifactDiff

ArtifactDiff is a local-first prototype that checks whether a contract edit matches a
policy approved before editing. You declare the allowed clause change; the tool inspects
a candidate DOCX or text-based PDF and returns `PASS`, `REVIEW`, or `FAIL`, then stores
a content-addressed Review Bundle that can be verified later.

ArtifactDiff 是本地运行的合同修改核验原型：先指定允许的条款修改，再检查候选 DOCX
或带文字层的 PDF，给出 `PASS` / `REVIEW` / `FAIL`，并保存可校验的审查记录。

> Status: `0.1.0` alpha. The signed synthetic Golden Path is implemented, and the
> repository has a large automated test suite. Broader real-contract evaluation and
> public packaging remain in progress. There is no PyPI release and no demo GIF in
> this repository.

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

Requires Python 3.11+ and a local checkout. After dependencies are installed, the demo
generates synthetic contracts and makes no network request.

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
approve its own finding. See the
[Golden Path walkthrough](examples/contract-golden-path/README.md).

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

The Review Bundle stores the policy, comparison facts, verdict, evidence index, and
signed events when verified assurance is enabled. The verifier recomputes digests and
signature claims from the bundle bytes.

## Interfaces

The same verdict and evidence data are available through:

- **CLI:** create, validate, and seal policies; run verification; inspect findings;
  record human decisions; verify or pack bundles.
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

For an MCP host, set absolute input and output roots before starting the stdio server.
Separate multiple roots with the platform path separator.

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
- Policy validation simulates declared edits and rejects selectors that cannot find
  the resulting clause. Use an unchanged context phrase as the selector anchor.
- Recognized parties, money, currencies, dates, durations, percentages, headers,
  footers, signatures, seals, and attachments are protected by default.
- Ed25519 signatures provide the implemented offline trust mechanism. Enterprise
  identity support is not implemented.
- Evidence defaults to `minimal`. `full` is explicit, and `sealed` encrypts evidence for
  named recipients.
- MCP responses are bounded and do not return full contracts, page images, or key
  material.

See [SECURITY.md](SECURITY.md) and the
[Golden Path acceptance record](docs/plan-4.5-contract-golden-path.md).

## Supported inputs and current limits

Implemented paths:

- DOCX compared with DOCX.
- Text-based PDF compared with text-based PDF.
- DOCX compared with a rendered PDF when LibreOffice rendering is configured.
- Selected English, Chinese, and bilingual contract examples.

Material limits:

- No OCR. A scanned PDF without extractable text cannot receive the same text
  verification as a text-based PDF.
- Multi-column PDFs, tables, and unusual reading orders can produce incorrect text
  grouping and need human review.
- Protected-value extraction uses deterministic patterns, not a legal NER model.
- The Golden Path uses synthetic contracts. Selected external-document tests do not
  establish production accuracy or a zero-false-pass rate.
- ArtifactDiff is an engineering prototype, not a substitute for legal review.

### Inspect helper: independent headings

Python `inspect_contract()` and the MCP `inspect_contract` tool may also return
`independent_headings` and `truncated_headings`. `independent_headings` is a bounded,
best-effort list of visible headings for reviewer inspection. Selectors and
authorization still use the clause tree. Hidden DOCX text is excluded.
`truncated_headings` reports when response limits shorten the heading output.
Multi-column PDF limits above still apply.

## Development

```console
python -m pip install -e ".[dev]"
python -m pytest -q
```

CI already runs on GitHub Actions for pushes and pull requests to `master`
(`.github/workflows/ci.yml`: ruff baseline checks, `mypy --strict`, and pytest on
Python 3.11, 3.12, and 3.13, plus a wheel build and install smoke test).

More documentation pointers: [docs/README.md](docs/README.md).

## Planned work

- Broader real-contract evaluation and a measured false-pass gate.
- A docs / binary-document pull-request review Action (**not implemented yet**;
  ordinary CI already exists as noted above).
- Publish schemas, a threat model, an SBOM, provenance, and a signed alpha release.
- Adapter boundaries for enterprise parsers, renderers, signing, encryption, and
  storage.

The project has one narrow goal: make an agent's permitted contract edit and the
evidence for its verdict inspectable before delivery.
