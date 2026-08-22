# Contract Golden Path

This example answers one concrete question:

> An AI agent was authorized to change a payment window from 30 days to 45 days. Did it
> change only that instruction, while preserving the rest of the contract?

The runner creates redistributable synthetic PDFs and executes three high-assurance
cases through the same application services used by the CLI, MCP adapter, and local
review desk.

| Case | Candidate change | Expected result |
| --- | --- | --- |
| `authorized` | Only `30 days` becomes `45 days` | `PASS` |
| `review` | Authorized edit plus an unexplained mark outside the edit envelope | blocking `REVIEW` |
| `unauthorized` | Authorized edit plus `Example Ltd.` becoming `Acme Corporation` | nonapprovable `FAIL` |

Every case uses an Ed25519-authorized frozen policy, an ArtifactDiff-controlled edit
session, a signed `verified` Review Bundle, and independent bundle verification.

## Run it

From an editable source checkout with development dependencies installed:

```console
python scripts/run_contract_golden_path.py --output build/contract-golden-path
```

The command prints the path to `summary.json`. The `review` case remains blocking by
default. This is intentional: ArtifactDiff never treats an unexplained visual change as
implicitly allowed.

To exercise the signed finding-decision path as part of the synthetic demo:

```console
python scripts/run_contract_golden_path.py \
  --output build/contract-golden-path-approved \
  --approve-review
```

`--approve-review` creates an explicit, finding-bound approval signed by the synthetic
human reviewer identity. It exists only to demonstrate the event-chain transition from
`REVIEW` to effective `PASS`; production approval remains an interactive human action
through `artifactdiff review` or `artifactdiff approve`.

## Inspect the result

The output contains:

- `inputs/`: synthetic baseline, draft and authorized frozen policy, and public trust
  metadata;
- `sessions/`: separate controlled candidate workspaces and signed session-open events;
- `bundles/`: immutable Review Bundles for all three cases;
- `summary.json`: raw/effective outcomes, assurance and signature state, finding IDs,
  approval IDs, and bundle locations.

No customer data or private key is used. The runner generates ephemeral in-memory keys,
writes only public trust metadata and signed artifacts, and never persists private-key
bytes.

## Acceptance test

```console
python -m pytest tests/acceptance/test_contract_golden_path.py -q
```

The acceptance test also attempts to approve the unauthorized party change and requires
ArtifactDiff to reject it with `fail findings cannot be approved`.
