"""A policy sealed in one process must load in another with a different hash seed."""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

_SEAL = """
import sys
from pathlib import Path
from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
from artifactdiff.policy.models import AllowRule
from artifactdiff.trust import TrustStore
from tests.factories import make_contract_docx

root = Path(sys.argv[1])
baseline = make_contract_docx(root / "baseline.docx", language="en")
application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
policy = application.draft_policy(
    baseline,
    ClauseSelector(clause_label="article ii", heading="Payment Terms", anchor="within"),
    before="30 days",
    after="45 days",
    rule_id="payment-window",
)
policy = policy.model_copy(
    update={
        "allow": [
            AllowRule(
                selector=policy.expect[0].selector,
                kinds=frozenset({"added", "removed", "modified"}),
            )
        ]
    }
)
policy_path = application.write_policy(policy, root / "policy.json")
application.seal_policy(baseline, policy_path, root / "sealed-policy.json")
"""

_LOAD = """
import sys
from pathlib import Path
from artifactdiff.session.service import load_sealed_policy

load_sealed_policy(Path(sys.argv[1]) / "sealed-policy.json")
"""


def _run(code: str, root: Path, seed: int) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": str(REPO_ROOT)}
    return subprocess.run(
        [sys.executable, "-c", code, str(root)],
        capture_output=True,
        text=True,
        env=environment,
        cwd=REPO_ROOT,
        timeout=120,
    )


def test_sealed_policy_loads_under_a_different_hash_seed(tmp_path: Path) -> None:
    sealed = _run(_SEAL, tmp_path, seed=1)
    assert sealed.returncode == 0, sealed.stderr
    for seed in (2, 3, 4, 5):
        loaded = _run(_LOAD, tmp_path, seed=seed)
        assert loaded.returncode == 0, f"PYTHONHASHSEED={seed}: {loaded.stderr[-400:]}"
