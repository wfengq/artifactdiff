"""MCP-specific filesystem-root configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from artifactdiff.errors import PathSafetyError
from artifactdiff.fs_safety import PathPolicy

_INPUT_ROOTS = "ARTIFACTDIFF_MCP_INPUT_ROOTS"
_OUTPUT_ROOTS = "ARTIFACTDIFF_MCP_OUTPUT_ROOTS"
_TRUST_STORE = "ARTIFACTDIFF_MCP_TRUST_STORE"


def _read_roots(variable: str) -> tuple[Path, ...]:
    value = os.environ.get(variable)
    if value is None:
        return ()
    components = value.split(os.pathsep)
    if not components or any(not item for item in components):
        raise PathSafetyError(f"{variable} must contain absolute paths without empty components")
    roots = tuple(Path(item) for item in components)
    if any(not root.is_absolute() for root in roots):
        raise PathSafetyError(f"{variable} must contain only absolute paths")
    return roots


def trust_store_path_from_environment() -> Path | None:
    """Read one absolute trust-store path without touching the filesystem."""
    value = os.environ.get(_TRUST_STORE)
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise PathSafetyError(f"{_TRUST_STORE} must contain an absolute path")
    return path


@dataclass(frozen=True, slots=True)
class McpRoots:
    """Independent input and output roots for MCP file tools."""

    inputs: tuple[Path, ...] = ()
    outputs: tuple[Path, ...] = ()

    @classmethod
    def from_environment(cls) -> McpRoots:
        """Read fail-closed MCP root configuration from the environment."""
        return cls(inputs=_read_roots(_INPUT_ROOTS), outputs=_read_roots(_OUTPUT_ROOTS))

    @property
    def enabled(self) -> bool:
        return bool(self.inputs and self.outputs)

    def path_policy(self) -> PathPolicy:
        """Build the shared resolved boundary once both root sets are configured."""
        if not self.enabled:
            raise PathSafetyError(
                "MCP file tools are disabled until input and output roots are configured"
            )
        return PathPolicy(input_roots=self.inputs, output_roots=self.outputs)
