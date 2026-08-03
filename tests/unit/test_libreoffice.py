import subprocess
from pathlib import Path

import pytest

import artifactdiff.libreoffice as libreoffice_module
from artifactdiff.errors import RenderUnavailableError
from artifactdiff.libreoffice import convert_docx_to_pdf, find_libreoffice


def test_find_libreoffice_prefers_explicit_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "soffice.exe"
    executable.write_bytes(b"")
    monkeypatch.setenv("ARTIFACTDIFF_LIBREOFFICE", str(executable))

    assert find_libreoffice() == executable.resolve()


def test_conversion_uses_argument_array_and_isolated_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")
    expected = tmp_path / "out" / "input.pdf"
    expected.parent.mkdir()
    expected.write_bytes(b"%PDF")

    converted = convert_docx_to_pdf(source, expected.parent, tmp_path / "soffice")

    assert converted == expected
    args, kwargs = calls[0]
    assert args[0] == str(tmp_path / "soffice")
    assert args[1].startswith("-env:UserInstallation=file:///")
    assert args[2:] == [
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        str(expected.parent),
        str(source),
    ]
    assert kwargs == {
        "shell": False,
        "check": False,
        "capture_output": True,
        "text": True,
        "timeout": 120,
    }


def test_find_libreoffice_rejects_directory_and_missing_fallbacks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ARTIFACTDIFF_LIBREOFFICE", str(tmp_path))
    monkeypatch.setattr(libreoffice_module.shutil, "which", lambda command: None)
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramW6432"):
        monkeypatch.delenv(variable, raising=False)

    assert find_libreoffice() is None


def test_conversion_maps_timeout_to_render_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def time_out(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args, 120)

    monkeypatch.setattr(subprocess, "run", time_out)
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")

    with pytest.raises(RenderUnavailableError, match="timed out"):
        convert_docx_to_pdf(source, tmp_path / "out", tmp_path / "soffice")


def test_conversion_maps_missing_executable_to_render_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def missing(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("missing")

    monkeypatch.setattr(subprocess, "run", missing)
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")

    with pytest.raises(RenderUnavailableError, match="unavailable"):
        convert_docx_to_pdf(source, tmp_path / "out", tmp_path / "soffice")


def test_conversion_rejects_nonzero_exit_even_when_pdf_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 2, "", "conversion failed")

    monkeypatch.setattr(subprocess, "run", fail)
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "input.pdf").write_bytes(b"%PDF")

    with pytest.raises(RenderUnavailableError, match="conversion failed"):
        convert_docx_to_pdf(source, output_dir, tmp_path / "soffice")


def test_conversion_rejects_success_without_output_pdf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def no_output(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", no_output)
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")

    with pytest.raises(RenderUnavailableError, match="no PDF was produced"):
        convert_docx_to_pdf(source, tmp_path / "out", tmp_path / "soffice")


def test_conversion_uses_a_distinct_profile_for_each_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profiles: list[str] = []

    def record(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        profiles.append(args[1])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", record)
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "input.pdf").write_bytes(b"%PDF")

    convert_docx_to_pdf(source, output_dir, tmp_path / "soffice")
    convert_docx_to_pdf(source, output_dir, tmp_path / "soffice")

    assert len(profiles) == 2
    assert profiles[0] != profiles[1]


def test_conversion_maps_output_directory_creation_error_to_render_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "input.docx"
    source.write_bytes(b"fixture")
    output_dir = tmp_path / "read-only-render-workdir"
    original_mkdir = Path.mkdir

    def fail_output_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        if path == output_dir:
            raise PermissionError("read-only render workdir")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_output_mkdir)

    with pytest.raises(RenderUnavailableError) as error:
        convert_docx_to_pdf(source, output_dir, tmp_path / "soffice")

    assert str(source) in str(error.value)
    assert "read-only render workdir" in str(error.value)
