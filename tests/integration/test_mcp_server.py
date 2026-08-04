import json
from hashlib import sha256
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from artifactdiff.errors import InputValidationError
from artifactdiff.mcp_server import (
    _absolute_output_dir,
    compare_documents_tool,
    inspect_document_tool,
    mcp,
)
from tests.factories import make_docx, make_pdf


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _make_changed_pdf_pair(tmp_path: Path) -> tuple[Path, Path]:
    pages = [[(72, 720, "Revenue 100")], [(72, 720, "Notes")]]
    before = make_pdf(tmp_path / "before.pdf", pages)
    after = make_pdf(tmp_path / "after.pdf", pages)
    after.write_bytes(after.read_bytes().replace(b"Revenue 100", b"Revenue 101"))
    return before, after


@pytest.mark.anyio
async def test_compare_tool_requires_absolute_paths() -> None:
    result = await compare_documents_tool("before.pdf", "after.pdf")

    assert result["ok"] is False
    assert result["error_type"] == "InputValidationError"
    assert "absolute" in str(result["error"])


@pytest.mark.anyio
async def test_compare_tool_returns_bounded_structured_result(tmp_path: Path) -> None:
    before, after = _make_changed_pdf_pair(tmp_path)

    result = await compare_documents_tool(
        str(before),
        str(after),
        str(tmp_path / "out"),
        visual=False,
    )

    assert result["ok"] is True
    assert result["status"] == "changed"
    assert Path(str(result["reports"]["json"])).is_absolute()
    assert "data:image" not in json.dumps(result)


@pytest.mark.anyio
async def test_server_discovers_exact_public_tool_names() -> None:
    async with create_connected_server_and_client_session(mcp) as session:
        response = await session.list_tools()

    assert {tool.name for tool in response.tools} == {
        "compare_documents",
        "inspect_document",
    }


@pytest.mark.anyio
async def test_inspect_tool_truncates_document_to_one_hundred_blocks(tmp_path: Path) -> None:
    source = make_docx(
        tmp_path / "large.docx",
        heading="Inventory",
        paragraphs=[f"Item {index}" for index in range(150)],
        rows=[["Name", "Value"]],
    )

    result = await inspect_document_tool(str(source))

    assert result["ok"] is True
    assert result["truncated"] is True
    assert len(result["blocks"]) == 100
    assert Path(str(result["path"])).is_absolute()


@pytest.mark.anyio
async def test_inspect_tool_returns_structured_error_for_relative_path() -> None:
    result = await inspect_document_tool("document.docx")

    assert result == {
        "ok": False,
        "error_type": "InputValidationError",
        "error": "Path must be absolute: document.docx",
    }


@pytest.mark.anyio
async def test_compare_tool_rejects_relative_output_directory(tmp_path: Path) -> None:
    before, after = _make_changed_pdf_pair(tmp_path)

    result = await compare_documents_tool(
        str(before),
        str(after),
        "reports",
        visual=False,
    )

    assert result["ok"] is False
    assert result["error_type"] == "InputValidationError"
    assert "absolute" in str(result["error"])
    assert not (tmp_path / "reports").exists()


def test_output_directory_must_be_absolute_before_user_expansion(tmp_path: Path) -> None:
    with pytest.raises(InputValidationError, match="absolute"):
        _absolute_output_dir("~/reports", tmp_path / "before.pdf", tmp_path / "after.pdf")


@pytest.mark.anyio
async def test_compare_tool_uses_deterministic_default_output_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = _make_changed_pdf_pair(tmp_path)
    monkeypatch.chdir(tmp_path)
    expected_name = f"{sha256(before.read_bytes()).hexdigest()[:12]}-{sha256(after.read_bytes()).hexdigest()[:12]}"

    result = await compare_documents_tool(str(before), str(after), visual=False)

    assert result["ok"] is True
    assert Path(str(result["reports"]["json"])).parent == (
        tmp_path / "artifactdiff-reports" / expected_name
    )


@pytest.mark.anyio
async def test_compare_tool_limits_key_changes_to_twenty(tmp_path: Path) -> None:
    before = make_docx(
        tmp_path / "before.docx",
        heading="Items",
        paragraphs=[f"Item {index}: old value" for index in range(25)],
        rows=[["Name", "Value"]],
    )
    after = make_docx(
        tmp_path / "after.docx",
        heading="Items",
        paragraphs=[f"Item {index}: new value" for index in range(25)],
        rows=[["Name", "Value"]],
    )

    result = await compare_documents_tool(
        str(before),
        str(after),
        str(tmp_path / "out"),
        visual=False,
    )

    assert result["ok"] is True
    assert result["summary"]["total_changes"] > 20
    assert len(result["changes"]) == 20
    assert result["truncated_changes"] is True
