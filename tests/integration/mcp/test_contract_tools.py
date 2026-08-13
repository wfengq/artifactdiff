from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
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
        "event_chain_valid": True,
        "errors": [],
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
        outputs / "signed.json",
    )
    destination = outputs / "forbidden-bundle"

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
