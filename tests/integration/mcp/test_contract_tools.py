from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import InputValidationError
from artifactdiff.mcp_paths import McpRoots
from artifactdiff.mcp_server import create_mcp, mcp
from artifactdiff.session import SealedPolicyArtifact, write_sealed_policy
from artifactdiff.trust import TrustStore
from tests.factories import make_contract_docx


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_mcp_exposes_bounded_contract_tools_but_no_approval() -> None:
    """Dropping a contract tool or registering approval authority changes the public boundary."""
    async with create_connected_server_and_client_session(mcp) as session:
        response = await session.list_tools()

    names = {tool.name for tool in response.tools}
    assert names == {
        "compare_documents",
        "inspect_document",
        "inspect_contract",
        "draft_contract_policy",
        "validate_contract_policy",
        "seal_local_policy",
        "verify_contract_change",
        "list_review_findings",
        "get_review_finding",
        "verify_review_bundle",
    }
    assert not any("approve" in name or "sign_verified" in name for name in names)


async def _call(mcp, name: str, arguments: dict[str, object]) -> dict[str, object]:
    async with create_connected_server_and_client_session(mcp) as session:
        response = await session.call_tool(name, arguments)
    assert response.structuredContent is not None
    return dict(response.structuredContent)


@pytest.fixture
def configured_mcp(tmp_path: Path):
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    inputs.mkdir()
    outputs.mkdir()
    return create_mcp(McpRoots(inputs=(inputs,), outputs=(outputs,)))


def _contract_pair(root: Path) -> tuple[Path, Path]:
    baseline = make_contract_docx(root / "baseline.docx", language="en", payment_days=30)
    candidate = make_contract_docx(root / "candidate.docx", language="en", payment_days=45)
    return baseline, candidate


@pytest.mark.anyio
async def test_mcp_contract_workflow_returns_only_bounded_public_fields(
    configured_mcp, tmp_path: Path
) -> None:
    """Returning contract bodies, page bytes, or unbounded findings exposes private review data."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, candidate = _contract_pair(inputs)
    full_contract_text = "The parties enter this agreement on equal terms."

    inspection = await _call(configured_mcp, "inspect_contract", {"path": str(baseline)})
    assert inspection["ok"] is True
    assert len(inspection["clauses"]) <= 20
    assert full_contract_text not in json.dumps(inspection)

    drafted = await _call(
        configured_mcp,
        "draft_contract_policy",
        {
            "baseline_path": str(baseline),
            "clause_label": "Article II",
            "heading": "Payment Terms",
            "anchor": "Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
            "before": "30 days",
            "after": "45 days",
            "rule_id": "payment-window",
        },
    )
    assert drafted["ok"] is True
    assert len(drafted["policy_sha256"]) == 64
    assert len(drafted["selector_candidates"]) <= 20
    policy_path = inputs / "policy.json"
    policy_path.write_text(json.dumps(drafted["policy"]), encoding="utf-8")

    validated = await _call(
        configured_mcp,
        "validate_contract_policy",
        {"baseline_path": str(baseline), "policy_path": str(policy_path)},
    )
    assert validated["ok"] is True
    assert validated["policy_sha256"] == drafted["policy_sha256"]

    sealed = await _call(
        configured_mcp,
        "seal_local_policy",
        {
            "baseline_path": str(baseline),
            "policy_path": str(policy_path),
            "output_path": str(outputs / "sealed.json"),
        },
    )
    assert sealed["ok"] is True
    sealed_path = Path(str(sealed["sealed_policy_path"]))
    assert sealed_path.is_file()

    verified = await _call(
        configured_mcp,
        "verify_contract_change",
        {
            "baseline_path": str(baseline),
            "candidate_path": str(candidate),
            "sealed_policy_path": str(sealed_path),
            "output_path": str(outputs / "bundle"),
            "visual": False,
        },
    )
    assert verified["ok"] is True, verified
    assert verified["assurance"] == "local"
    assert len(verified["findings"]) <= 20
    assert Path(str(verified["bundle_path"])).is_absolute()
    encoded = json.dumps(verified, ensure_ascii=False)
    assert "BEGIN PRIVATE KEY" not in encoded
    assert "data:image" not in encoded
    assert full_contract_text not in encoded

    bundle = await _call(
        configured_mcp,
        "verify_review_bundle",
        {"bundle_path": str(verified["bundle_path"])},
    )
    assert bundle == {
        "ok": True,
        "valid": True,
        "assurance": "local",
        "signature_valid_at_creation": None,
        "currently_trusted": None,
        "effective_outcome": verified["effective_verdict"],
    }


@pytest.mark.anyio
async def test_mcp_rejects_output_symlink_before_sealing(configured_mcp, tmp_path: Path) -> None:
    """Following a swapped output child symlink would write policy material outside MCP roots."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, _ = _contract_pair(inputs)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor="Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, inputs / "policy.json")
    outside = tmp_path / "outside"
    outside.mkdir()
    escape = outputs / "escape"
    try:
        escape.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")

    response = await _call(
        configured_mcp,
        "seal_local_policy",
        {
            "baseline_path": str(baseline),
            "policy_path": str(policy_path),
            "output_path": str(escape / "sealed.json"),
        },
    )

    assert response["ok"] is False
    assert response["error_type"] == "PathSafetyError"
    assert list(outside.iterdir()) == []


@pytest.mark.anyio
async def test_mcp_rejects_signed_policy_without_creating_verification_output(
    configured_mcp, bundle_fixture: object, tmp_path: Path
) -> None:
    """Letting MCP verify signed work would bypass its controlled-session and manifest authority."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, candidate = _contract_pair(inputs)
    signed = write_sealed_policy(
        SealedPolicyArtifact(
            frozen=bundle_fixture.frozen, authorization=bundle_fixture.authorization
        ),
        inputs / "signed.json",
    )
    destination = outputs / "forbidden" / "bundle"

    response = await _call(
        configured_mcp,
        "verify_contract_change",
        {
            "baseline_path": str(baseline),
            "candidate_path": str(candidate),
            "sealed_policy_path": str(signed),
            "output_path": str(destination),
            "visual": False,
        },
    )

    assert response["ok"] is False
    assert response["error_type"] == "SessionError"
    assert "controlled CLI or enterprise runner" in str(response["error"])
    assert not destination.exists()
    assert not destination.parent.exists()


@pytest.mark.anyio
async def test_mcp_rejects_an_unregistered_output_policy_before_verification(
    configured_mcp, tmp_path: Path
) -> None:
    """Treating any output-root policy as generated lets a caller smuggle arbitrary artifacts."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, candidate = _contract_pair(inputs)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor="Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, inputs / "policy.json")
    sealed = application.seal_policy(baseline, policy_path, outputs / "unregistered.json")

    response = await _call(
        configured_mcp,
        "verify_contract_change",
        {
            "baseline_path": str(baseline),
            "candidate_path": str(candidate),
            "sealed_policy_path": str(sealed),
            "output_path": str(outputs / "bundle"),
            "visual": False,
        },
    )

    assert response["ok"] is False
    assert response["error_type"] == "PathSafetyError"
    assert not (outputs / "bundle").exists()


@pytest.mark.anyio
async def test_mcp_loads_a_registered_sealed_policy_once(
    configured_mcp, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A separate authorization check and verification load leaves a swap window between reads."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, candidate = _contract_pair(inputs)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor="Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, inputs / "policy.json")
    sealed = await _call(
        configured_mcp,
        "seal_local_policy",
        {
            "baseline_path": str(baseline),
            "policy_path": str(policy_path),
            "output_path": str(outputs / "sealed.json"),
        },
    )
    original = __import__("artifactdiff.application", fromlist=["load_sealed_policy"])
    calls = 0
    real_load = original.load_sealed_policy

    def counted(path: Path):
        nonlocal calls
        calls += 1
        return real_load(path)

    monkeypatch.setattr(original, "load_sealed_policy", counted)
    response = await _call(
        configured_mcp,
        "verify_contract_change",
        {
            "baseline_path": str(baseline),
            "candidate_path": str(candidate),
            "sealed_policy_path": str(sealed["sealed_policy_path"]),
            "output_path": str(outputs / "bundle"),
            "visual": False,
        },
    )

    assert response["ok"] is True
    assert calls == 0


@pytest.mark.anyio
async def test_mcp_rejects_a_sealed_policy_output_as_a_review_bundle(
    configured_mcp, tmp_path: Path
) -> None:
    """A generated artifact capability must be bound to its kind, not merely its output path."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, _ = _contract_pair(inputs)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor="Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, inputs / "policy.json")
    sealed = await _call(
        configured_mcp,
        "seal_local_policy",
        {
            "baseline_path": str(baseline),
            "policy_path": str(policy_path),
            "output_path": str(outputs / "sealed.json"),
        },
    )

    response = await _call(
        configured_mcp,
        "verify_review_bundle",
        {"bundle_path": str(sealed["sealed_policy_path"])},
    )

    assert response["ok"] is False
    assert response["error_type"] == "PathSafetyError"


@pytest.mark.anyio
async def test_mcp_rejects_a_swapped_registered_sealed_policy(
    configured_mcp, tmp_path: Path
) -> None:
    """Replacing an output file after registration must not change the sealed artifact in use."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, candidate = _contract_pair(inputs)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor="Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, inputs / "policy.json")
    sealed = await _call(
        configured_mcp,
        "seal_local_policy",
        {
            "baseline_path": str(baseline),
            "policy_path": str(policy_path),
            "output_path": str(outputs / "sealed.json"),
        },
    )
    sealed_path = Path(str(sealed["sealed_policy_path"]))
    sealed_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    sealed_path.write_bytes(b"swapped")
    destination = outputs / "not-created" / "bundle"

    response = await _call(
        configured_mcp,
        "verify_contract_change",
        {
            "baseline_path": str(baseline),
            "candidate_path": str(candidate),
            "sealed_policy_path": str(sealed_path),
            "output_path": str(destination),
            "visual": False,
        },
    )

    assert response["ok"] is True
    assert Path(str(response["bundle_path"])).is_dir()


@pytest.mark.anyio
async def test_mcp_rejects_a_tampered_registered_review_bundle(
    configured_mcp, tmp_path: Path
) -> None:
    """Replacing bundle files after capture must not alter the cached review snapshot."""
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    baseline, candidate = _contract_pair(inputs)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor="Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 within 30 days with a 5% late fee.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, inputs / "policy.json")
    sealed = await _call(
        configured_mcp,
        "seal_local_policy",
        {
            "baseline_path": str(baseline),
            "policy_path": str(policy_path),
            "output_path": str(outputs / "sealed.json"),
        },
    )
    verified = await _call(
        configured_mcp,
        "verify_contract_change",
        {
            "baseline_path": str(baseline),
            "candidate_path": str(candidate),
            "sealed_policy_path": str(sealed["sealed_policy_path"]),
            "output_path": str(outputs / "bundle"),
            "visual": False,
        },
    )
    bundle = Path(str(verified["bundle_path"]))
    verdict = bundle / "core" / "verdict.json"
    verdict.chmod(stat.S_IWRITE | stat.S_IREAD)
    verdict.write_text("{}", encoding="utf-8")

    response = await _call(configured_mcp, "verify_review_bundle", {"bundle_path": str(bundle)})

    assert response == {
        "ok": True,
        "valid": True,
        "assurance": "local",
        "signature_valid_at_creation": None,
        "currently_trusted": None,
        "effective_outcome": verified["effective_verdict"],
    }


@pytest.mark.anyio
async def test_mcp_rejects_an_oversized_draft_anchor_before_loading_contract(
    configured_mcp, tmp_path: Path
) -> None:
    """Echoing an unbounded anchor in a canonical policy leaks the caller's contract text."""
    sentinel = "FULL-CONTRACT-SENTINEL-" * 200

    response = await _call(
        configured_mcp,
        "draft_contract_policy",
        {
            "baseline_path": str(tmp_path / "inputs" / "does-not-exist.docx"),
            "clause_label": "Article II",
            "heading": "Payment Terms",
            "anchor": sentinel,
            "before": "30 days",
            "after": "45 days",
            "rule_id": "payment-window",
        },
    )

    assert response["ok"] is False
    assert response["error_type"] == InputValidationError.__name__
    assert sentinel not in str(response["error"])


@pytest.mark.anyio
async def test_mcp_rejects_an_aggregate_unicode_draft_before_baseline_access(
    configured_mcp, tmp_path: Path
) -> None:
    """Per-field character limits alone allow a large multibyte contract request through preflight."""
    response = await _call(
        configured_mcp,
        "draft_contract_policy",
        {
            "baseline_path": str(tmp_path / "inputs" / "forbidden.docx"),
            "clause_label": "条" * 256,
            "heading": "款" * 512,
            "anchor": "锚" * 2_000,
            "ancestor_path": ["路" * 256 for _ in range(16)],
            "before": "前" * 4_000,
            "after": "后" * 4_000,
            "rule_id": "r" * 64,
        },
    )

    assert response == {
        "ok": False,
        "error_type": "InputValidationError",
        "error": "draft request exceeds the MCP aggregate limit",
    }
