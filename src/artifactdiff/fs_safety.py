"""Resolved input/output path boundaries for high-assurance workflows."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from artifactdiff.errors import PathSafetyError


def _contains(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def _resolve_root(root: Path) -> Path:
    try:
        resolved = root.expanduser().resolve(strict=True)
    except OSError:
        raise PathSafetyError("configured path root is unavailable") from None
    if not resolved.is_dir():
        raise PathSafetyError("configured path root must be a directory")
    return resolved


def _roots(roots: tuple[Path, ...], *, label: str) -> tuple[Path, ...]:
    if not roots:
        raise PathSafetyError(f"at least one {label} root is required")
    resolved = tuple(_resolve_root(root) for root in roots)
    if len(resolved) != len(set(resolved)):
        raise PathSafetyError(f"{label} roots must be unique")
    return resolved


@dataclass(frozen=True, slots=True)
class PathPolicy:
    """Separate resolved allow roots for immutable inputs and new outputs."""

    input_roots: tuple[Path, ...]
    output_roots: tuple[Path, ...]

    def __post_init__(self) -> None:
        inputs = _roots(self.input_roots, label="input")
        outputs = _roots(self.output_roots, label="output")
        if any(
            _contains(input_root, output_root) or _contains(output_root, input_root)
            for input_root in inputs
            for output_root in outputs
        ):
            raise PathSafetyError("input and output roots must be disjoint")
        object.__setattr__(self, "input_roots", inputs)
        object.__setattr__(self, "output_roots", outputs)

    @staticmethod
    def _recheck_root(root: Path) -> None:
        try:
            if root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
                raise PathSafetyError("configured path root changed")
        except OSError:
            raise PathSafetyError("configured path root changed") from None

    def resolve_input(self, path: Path) -> Path:
        """Resolve an existing input and reject any root escape."""
        resolved = self._resolve_existing_input(path)
        if not resolved.is_file():
            raise PathSafetyError("input path is outside configured roots")
        return resolved

    def resolve_input_directory(self, path: Path) -> Path:
        """Resolve an existing directory input and reject any root escape."""
        resolved = self._resolve_existing_input(path)
        if not resolved.is_dir():
            raise PathSafetyError("input directory is outside configured roots")
        return resolved

    def _resolve_existing_input(self, path: Path) -> Path:
        for root in self.input_roots:
            self._recheck_root(root)
        try:
            resolved = path.expanduser().resolve(strict=True)
        except OSError:
            raise PathSafetyError("input path is unavailable") from None
        if not any(_contains(root, resolved) for root in self.input_roots):
            raise PathSafetyError("input path is outside configured roots")
        return resolved

    def resolve_output(self, path: Path) -> Path:
        """Create output parents one level at a time and recheck containment."""
        for root in self.output_roots:
            self._recheck_root(root)
        lexical = Path(os.path.abspath(path.expanduser()))
        roots = [root for root in self.output_roots if _contains(root, lexical)]
        if len(roots) != 1:
            raise PathSafetyError("output path is outside configured roots")
        root = roots[0]
        relative = lexical.relative_to(root)
        if not relative.parts:
            return root

        current = root
        for component in relative.parts[:-1]:
            destination = current / component
            if destination.is_symlink():
                raise PathSafetyError("output path must not contain a symbolic link")
            try:
                destination.mkdir()
            except FileExistsError:
                if not destination.is_dir():
                    raise PathSafetyError("output parent must be a directory") from None
            except OSError:
                raise PathSafetyError("output parent could not be created") from None
            try:
                current = destination.resolve(strict=True)
            except OSError:
                raise PathSafetyError("output parent could not be resolved") from None
            if not _contains(root, current):
                raise PathSafetyError("output path escaped its configured root")

        candidate = current / relative.parts[-1]
        if candidate.is_symlink():
            raise PathSafetyError("output destination must not be a symbolic link")
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            raise PathSafetyError("output destination could not be resolved") from None
        if not _contains(root, resolved):
            raise PathSafetyError("output path escaped its configured root")
        return resolved
