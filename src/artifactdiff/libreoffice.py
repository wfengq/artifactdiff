"""Safe LibreOffice discovery and isolated DOCX-to-PDF conversion."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from artifactdiff.errors import RenderUnavailableError


def _existing_file(value: str | Path | None) -> Path | None:
    if not value:
        return None
    candidate = Path(value).expanduser()
    try:
        if candidate.is_file():
            return candidate.resolve()
    except OSError:
        return None
    return None


def find_libreoffice() -> Path | None:
    """Find a concrete LibreOffice executable without invoking a shell."""
    explicit = _existing_file(os.environ.get("ARTIFACTDIFF_LIBREOFFICE"))
    if explicit is not None:
        return explicit

    for command in ("soffice", "libreoffice"):
        discovered = _existing_file(shutil.which(command))
        if discovered is not None:
            return discovered

    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramW6432"):
        root = os.environ.get(variable)
        if root:
            discovered = _existing_file(Path(root) / "LibreOffice" / "program" / "soffice.exe")
            if discovered is not None:
                return discovered
    return None


def convert_docx_to_pdf(source: Path, output_dir: Path, executable: Path) -> Path:
    """Convert one DOCX with an isolated profile and return the resulting PDF."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(
            prefix=".libreoffice-profile-", dir=output_dir, ignore_cleanup_errors=True
        ) as profile_name:
            profile = Path(profile_name)
            args = [
                str(executable),
                f"-env:UserInstallation={profile.resolve().as_uri()}",
                "--headless",
                "--convert-to",
                "pdf",
                "--outdir",
                str(output_dir),
                str(source),
            ]
            completed = subprocess.run(
                args,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
    except subprocess.TimeoutExpired as error:
        raise RenderUnavailableError(f"LibreOffice timed out rendering {source}") from error
    except OSError as error:
        raise RenderUnavailableError(f"LibreOffice is unavailable for {source}: {error}") from error

    converted = output_dir / f"{source.stem}.pdf"
    if completed.returncode != 0 or not converted.is_file():
        detail = completed.stderr.strip() or completed.stdout.strip() or "no PDF was produced"
        raise RenderUnavailableError(f"LibreOffice could not render {source}: {detail}")
    return converted
