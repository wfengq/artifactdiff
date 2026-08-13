from __future__ import annotations

import os
from pathlib import Path

import pytest

from artifactdiff.errors import PathSafetyError
from artifactdiff.mcp_paths import McpRoots


def test_mcp_roots_default_to_disabled_file_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Treating absent root settings as the current directory grants accidental file access."""
    monkeypatch.delenv("ARTIFACTDIFF_MCP_INPUT_ROOTS", raising=False)
    monkeypatch.delenv("ARTIFACTDIFF_MCP_OUTPUT_ROOTS", raising=False)

    assert McpRoots.from_environment() == McpRoots()


@pytest.mark.parametrize("suffix", ["relative", ""])
@pytest.mark.parametrize(
    "variable", ["ARTIFACTDIFF_MCP_INPUT_ROOTS", "ARTIFACTDIFF_MCP_OUTPUT_ROOTS"]
)
def test_mcp_roots_reject_relative_or_empty_path_components(
    monkeypatch: pytest.MonkeyPatch, variable: str, suffix: str, tmp_path: Path
) -> None:
    """A relative or empty component can silently widen the MCP filesystem boundary."""
    value = f"relative{os.pathsep}{tmp_path}" if suffix == "relative" else f"{tmp_path}{os.pathsep}"
    monkeypatch.setenv(variable, value)

    with pytest.raises(PathSafetyError):
        McpRoots.from_environment()


def test_mcp_roots_build_a_disjoint_path_policy(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    inputs.mkdir()
    outputs.mkdir()

    policy = McpRoots(inputs=(inputs,), outputs=(outputs,)).path_policy()

    assert policy.resolve_input_directory(inputs) == inputs
    assert policy.resolve_output(outputs / "bundle") == outputs / "bundle"
