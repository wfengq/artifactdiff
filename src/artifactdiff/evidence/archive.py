"""Deterministic and path-safe Review Bundle archives."""

from __future__ import annotations

import hashlib
import re
import secrets
import shutil
import tarfile
import unicodedata
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import IO

from pydantic import ValidationError

from artifactdiff.bundle.digests import canonical_bytes, canonical_digest
from artifactdiff.bundle.models import BundleAssurance, BundleManifest
from artifactdiff.errors import EvidenceError
from artifactdiff.evidence.age_cli import AgeCliProvider
from artifactdiff.evidence.models import EvidenceIndex
from artifactdiff.policy import EvidenceMode
from artifactdiff.trust import SignatureEnvelope, SigningProvider, TrustRole

_ARCHIVE_PURPOSE = "evidence_archive"
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024
_APPROVAL_NAME = re.compile(r"^[0-9]{6}-approval\.json$")


def _remove(path: Path) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def _archive_entries(bundle: Path) -> list[tuple[str, Path]]:
    try:
        if bundle.is_symlink() or not bundle.is_dir():
            raise EvidenceError("invalid review bundle path")
        root = bundle.resolve(strict=True)
        manifest_path = root / "core" / "manifest.json"
        complete_path = root / "COMPLETE"
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or manifest_path.stat().st_size > 10 * 1024 * 1024
            or complete_path.is_symlink()
            or not complete_path.is_file()
        ):
            raise EvidenceError("review bundle is incomplete")
        manifest_raw = manifest_path.read_bytes()
        manifest = BundleManifest.model_validate_json(manifest_raw)
        if manifest_raw != canonical_bytes(manifest):
            raise EvidenceError("review bundle manifest is invalid")
        manifest_digest = canonical_digest(manifest)
        if (
            complete_path.stat().st_size != 64
            or complete_path.read_bytes() != manifest_digest.encode("ascii")
            or root.name != manifest_digest
        ):
            raise EvidenceError("review bundle completion digest is invalid")

        expected_files = {
            "COMPLETE",
            "core/manifest.json",
            *(payload.path for payload in manifest.payloads),
        }
        if manifest.assurance is not BundleAssurance.LOCAL:
            expected_files.add("core/manifest.sig")

        from artifactdiff.review.models import ApprovalEvent

        events = root / "events"
        if events.is_symlink() or not events.is_dir():
            raise EvidenceError("review bundle events directory is invalid")
        for approval_path in events.glob("*-approval.json"):
            if (
                approval_path.is_symlink()
                or not approval_path.is_file()
                or _APPROVAL_NAME.fullmatch(approval_path.name) is None
                or approval_path.stat().st_size > 10 * 1024 * 1024
            ):
                raise EvidenceError("review bundle approval event is invalid")
            approval_raw = approval_path.read_bytes()
            approval = ApprovalEvent.model_validate_json(approval_raw)
            if approval_raw != canonical_bytes(approval):
                raise EvidenceError("review bundle approval event is invalid")
            expected_files.add(approval_path.relative_to(root).as_posix())

        actual_files: set[str] = set()
        actual_directories: set[str] = set()
        for path in root.rglob("*"):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise EvidenceError("review bundle contains an unsafe path")
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                actual_directories.add(relative)
            else:
                actual_files.add(relative)
        if actual_files != expected_files:
            raise EvidenceError("review bundle contains an unregistered file")

        expected_directories = {"core", "core/evidence", "events"}
        for relative in expected_files:
            parent = PurePosixPath(relative).parent
            while parent.as_posix() != ".":
                expected_directories.add(parent.as_posix())
                parent = parent.parent
        if actual_directories != expected_directories:
            raise EvidenceError("review bundle contains an unregistered directory")

        payloads = {payload.path: payload for payload in manifest.payloads}
        for relative, payload in payloads.items():
            path = root / Path(relative)
            if (
                path.resolve(strict=True) != path
                or path.stat().st_size != payload.size_bytes
                or _file_digest(path) != payload.sha256
            ):
                raise EvidenceError("review bundle payload digest is invalid")

        entries = [(root.name, root)]
        for relative in sorted(actual_directories | actual_files):
            entries.append((f"{root.name}/{relative}", root / Path(relative)))
        return sorted(entries, key=lambda item: item[0])
    except EvidenceError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise EvidenceError("review bundle is unavailable") from None


def _bundle_evidence_mode(bundle: Path) -> EvidenceMode:
    try:
        index_path = bundle / "core" / "evidence" / "index.json"
        if (
            index_path.is_symlink()
            or not index_path.is_file()
            or index_path.stat().st_size > 10 * 1024 * 1024
        ):
            raise EvidenceError("bundle evidence index is invalid")
        raw = index_path.read_bytes()
        index = EvidenceIndex.model_validate_json(raw)
        if raw != canonical_bytes(index):
            raise EvidenceError("bundle evidence index is invalid")
        return index.mode
    except EvidenceError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise EvidenceError("bundle evidence index is invalid") from None


def _tar_info(name: str, path: Path) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if path.is_dir():
        info.type = tarfile.DIRTYPE
        info.mode = 0o700
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.mode = 0o600
        info.size = path.stat().st_size
    return info


def _write_tar(bundle: Path, output: Path) -> None:
    try:
        with tarfile.open(output, mode="x", format=tarfile.PAX_FORMAT) as archive:
            for name, path in _archive_entries(bundle):
                info = _tar_info(name, path)
                if path.is_dir():
                    archive.addfile(info)
                else:
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
    except EvidenceError:
        raise
    except (OSError, tarfile.TarError):
        raise EvidenceError("unable to pack review bundle") from None


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_signature(archive: Path, signer: SigningProvider) -> Path:
    signature_path = archive.with_name(f"{archive.name}.sig")
    temporary = archive.parent / f".{archive.name}.{secrets.token_hex(12)}.sig.tmp"
    try:
        signature = SignatureEnvelope.model_validate(
            signer.sign(
                purpose=_ARCHIVE_PURPOSE,
                digest=_file_digest(archive),
                required_role=TrustRole.ARCHIVE_SIGNER,
            )
        )
        if (
            signature.purpose != _ARCHIVE_PURPOSE
            or signature.canonical_object_sha256 != _file_digest(archive)
        ):
            raise EvidenceError("invalid archive signature")
        temporary.write_bytes(canonical_bytes(signature))
        temporary.replace(signature_path)
        return signature_path
    except EvidenceError:
        raise
    except (OSError, ValidationError, TypeError, ValueError):
        raise EvidenceError("unable to sign evidence archive") from None
    finally:
        _remove(temporary)


def pack_bundle(
    bundle: Path,
    output: Path,
    *,
    mode: EvidenceMode,
    recipients: Sequence[str] = (),
    age_provider: AgeCliProvider | None = None,
    archive_signer: SigningProvider | None = None,
) -> Path:
    """Pack a bundle into a deterministic tar, optionally sealed with age."""
    try:
        checked_mode = EvidenceMode(mode)
    except (TypeError, ValueError):
        raise EvidenceError("invalid evidence archive mode") from None
    if output.is_symlink() or output.exists():
        raise EvidenceError("evidence archive output must be new")
    if checked_mode is EvidenceMode.SEALED:
        if not recipients:
            raise EvidenceError("sealed archives require valid age recipients")
        if output.name.casefold().endswith(".tar.age") is False:
            raise EvidenceError("sealed archives must use the .tar.age suffix")
    else:
        if recipients or age_provider is not None:
            raise EvidenceError("age encryption requires sealed evidence mode")
        if output.suffix.casefold() != ".tar":
            raise EvidenceError("minimal and full archives must use the .tar suffix")
    contained_mode = _bundle_evidence_mode(bundle)
    if (checked_mode is EvidenceMode.MINIMAL and contained_mode is not EvidenceMode.MINIMAL) or (
        checked_mode is EvidenceMode.FULL and contained_mode is EvidenceMode.SEALED
    ):
        raise EvidenceError("bundle evidence exceeds requested privacy mode")

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.parent.is_symlink() or not output.parent.is_dir():
            raise EvidenceError("evidence archive destination is unsafe")
    except EvidenceError:
        raise
    except OSError:
        raise EvidenceError("evidence archive destination is unavailable") from None

    nonce = secrets.token_hex(12)
    temporary_tar = output.parent / f".{output.name}.{nonce}.tar.tmp"
    temporary_output = output.parent / f".{output.name}.{nonce}.tmp"
    signature_path: Path | None = None
    try:
        _write_tar(bundle, temporary_tar)
        if checked_mode is EvidenceMode.SEALED:
            provider = age_provider or AgeCliProvider(Path("age"))
            provider.encrypt(temporary_tar, temporary_output, list(recipients))
            if temporary_output.is_symlink() or not temporary_output.is_file():
                raise EvidenceError("age encryption failed")
        else:
            temporary_tar.replace(temporary_output)
        temporary_output.replace(output)
        if archive_signer is not None:
            signature_path = _write_signature(output, archive_signer)
        return output
    except EvidenceError:
        _remove(output)
        if signature_path is not None:
            _remove(signature_path)
        raise
    except OSError:
        _remove(output)
        if signature_path is not None:
            _remove(signature_path)
        raise EvidenceError("unable to publish evidence archive") from None
    finally:
        _remove(temporary_tar)
        _remove(temporary_output)


def _safe_member_parts(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or name.startswith("/")
        or unicodedata.normalize("NFC", name) != name
        or path.as_posix() != name
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        raise EvidenceError("unsafe archive member")
    return path.parts


def _copy_member(source: IO[bytes], destination: Path, expected_size: int) -> None:
    written = 0
    with destination.open("xb") as stream:
        while True:
            chunk = source.read(min(1024 * 1024, expected_size - written))
            if not chunk:
                break
            stream.write(chunk)
            written += len(chunk)
    if written != expected_size:
        raise EvidenceError("archive member size mismatch")


def extract_bundle_archive(archive: Path, destination: Path) -> Path:
    """Safely extract a plaintext bundle tar into a new destination."""
    if archive.is_symlink() or not archive.is_file():
        raise EvidenceError("evidence archive is unavailable")
    if destination.is_symlink() or destination.exists():
        raise EvidenceError("archive extraction destination must be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.parent / f".{destination.name}.{secrets.token_hex(12)}.tmp"
    try:
        staging.mkdir()
        with tarfile.open(archive, mode="r:") as stream:
            members = stream.getmembers()
            if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
                raise EvidenceError("unsafe archive member")
            names: set[str] = set()
            roots: set[str] = set()
            total_size = 0
            for member in members:
                parts = _safe_member_parts(member.name)
                roots.add(parts[0])
                if member.name in names or not (member.isdir() or member.isfile()):
                    raise EvidenceError("unsafe archive member")
                names.add(member.name)
                total_size += member.size
                if total_size > _MAX_EXTRACTED_BYTES:
                    raise EvidenceError("archive extraction limit exceeded")
                target = staging.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(exist_ok=True)
                    continue
                extracted = stream.extractfile(member)
                if extracted is None:
                    raise EvidenceError("unsafe archive member")
                with extracted:
                    _copy_member(extracted, target, member.size)
            if len(roots) != 1:
                raise EvidenceError("archive must contain one review bundle")
            root_name = next(iter(roots))
            bundle = staging / root_name
            if not bundle.is_dir() or not (bundle / "COMPLETE").is_file():
                raise EvidenceError("archive does not contain a complete review bundle")
        staging.replace(destination)
        return destination / root_name
    except EvidenceError:
        raise
    except (OSError, tarfile.TarError):
        raise EvidenceError("unable to extract evidence archive") from None
    finally:
        _remove(staging)
