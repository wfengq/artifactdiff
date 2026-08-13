import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from artifactdiff.mcp_paths import McpRoots
from artifactdiff.mcp_server import create_mcp
from tests.factories import make_docx, make_pdf


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def configured_mcp(tmp_path: Path):
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    inputs.mkdir()
    outputs.mkdir()
    return create_mcp(McpRoots(inputs=(inputs,), outputs=(outputs,)))


async def _call(mcp, name: str, arguments: dict[str, object]) -> dict[str, object]:
    async with create_connected_server_and_client_session(mcp) as session:
        response = await session.call_tool(name, arguments)
    assert response.structuredContent is not None
    return dict(response.structuredContent)


def _make_changed_pdf_pair(root: Path) -> tuple[Path, Path]:
    pages = [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]]
    before = make_pdf(root / "before.pdf", pages)
    after = make_pdf(root / "after.pdf", pages)
    after.write_bytes(after.read_bytes().replace(b"Revenue 100", b"Revenue 101"))
    return before, after


@pytest.mark.anyio
async def test_compare_tool_requires_configured_absolute_input_roots() -> None:
    response = await _call(
        create_mcp(McpRoots()),
        "compare_documents",
        {
            "before_path": "before.pdf",
            "after_path": "after.pdf",
        },
    )

    assert response["ok"] is False
    assert response["error_type"] == "PathSafetyError"


@pytest.mark.anyio
async def test_compare_tool_returns_bounded_structured_result(
    configured_mcp, tmp_path: Path
) -> None:
    before, after = _make_changed_pdf_pair(tmp_path / "inputs")

    result = await _call(
        configured_mcp,
        "compare_documents",
        {
            "before_path": str(before),
            "after_path": str(after),
            "output_dir": str(tmp_path / "outputs" / "out"),
            "visual": False,
        },
    )

    assert result["ok"] is True
    assert result["status"] == "changed"
    assert Path(str(result["reports"]["json"])).is_absolute()
    assert "data:image" not in json.dumps(result)


@pytest.mark.anyio
async def test_server_discovers_exact_public_tool_names(configured_mcp) -> None:
    async with create_connected_server_and_client_session(configured_mcp) as session:
        response = await session.list_tools()

    assert {tool.name for tool in response.tools} == {
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


@pytest.mark.anyio
async def test_inspect_tool_truncates_document_to_one_hundred_blocks(
    configured_mcp, tmp_path: Path
) -> None:
    source = make_docx(
        tmp_path / "inputs" / "large.docx",
        heading="Inventory",
        paragraphs=[f"Item {index}" for index in range(150)],
        rows=[["Name", "Value"]],
    )

    result = await _call(configured_mcp, "inspect_document", {"path": str(source)})

    assert result["ok"] is True
    assert result["truncated"] is True
    assert len(result["blocks"]) == 100
    assert Path(str(result["path"])).is_absolute()
    assert "Item 0" not in json.dumps(result)


@pytest.mark.anyio
async def test_compare_tool_rejects_an_output_outside_configured_roots(
    configured_mcp, tmp_path: Path
) -> None:
    before, after = _make_changed_pdf_pair(tmp_path / "inputs")
    outside = tmp_path / "outside"

    result = await _call(
        configured_mcp,
        "compare_documents",
        {
            "before_path": str(before),
            "after_path": str(after),
            "output_dir": str(outside / "reports"),
            "visual": False,
        },
    )

    assert result["ok"] is False
    assert result["error_type"] == "PathSafetyError"
    assert not outside.exists()


@pytest.mark.anyio
async def test_compare_tool_limits_key_changes_to_twenty(configured_mcp, tmp_path: Path) -> None:
    before = make_docx(
        tmp_path / "inputs" / "before.docx",
        heading="Items",
        paragraphs=[f"Item {index}: old value" for index in range(25)],
        rows=[["Name", "Value"]],
    )
    after = make_docx(
        tmp_path / "inputs" / "after.docx",
        heading="Items",
        paragraphs=[f"Item {index}: new value" for index in range(25)],
        rows=[["Name", "Value"]],
    )

    result = await _call(
        configured_mcp,
        "compare_documents",
        {
            "before_path": str(before),
            "after_path": str(after),
            "output_dir": str(tmp_path / "outputs" / "out"),
            "visual": False,
        },
    )

    assert result["ok"] is True
    assert result["summary"]["total_changes"] > 20
    assert len(result["changes"]) == 20
    assert result["truncated_changes"] is True


@pytest.mark.anyio
async def test_list_findings_rejects_a_page_size_above_one_hundred(configured_mcp) -> None:
    """An unconstrained findings page can turn a tool response into a bundle data exfiltration path."""
    result = await _call(
        configured_mcp,
        "list_review_findings",
        {"bundle_path": "C:\\not-read", "limit": 101},
    )

    assert result == {
        "ok": False,
        "error_type": "PathSafetyError",
        "error": "finding limit must be between 1 and 100",
    }
