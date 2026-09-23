"""Atomic content-addressed Review Bundle writer."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
from pathlib import Path

from pydantic import ValidationError

from artifactdiff.atomic import replace_directory
from artifactdiff.bundle.digests import canonical_bytes, canonical_digest, canonical_file_digest
from artifactdiff.bundle.models import BundleAssurance, BundleManifest, BundlePayload
from artifactdiff.errors import BundleError
from artifactdiff.evidence.models import EvidenceIndex
from artifactdiff.models import ComparisonResult
from artifactdiff.policy import (
    EvidenceMode,
    FrozenPolicy,
    frozen_policy_digest,
    validate_frozen_policy_integrity,
)
from artifactdiff.session import SessionOpenedEvent
from artifactdiff.trust import PolicyAuthorization, SignatureEnvelope, SigningProvider, TrustRole
from artifactdiff.verification.models import ContractChangeSet, RawVerdict
from artifactdiff.verification.reporting import VerificationRun

_MANIFEST_PURPOSE = "bundle_manifest"
_CORE_FILES = frozenset(
    {
        "core/policy.json",
        "core/comparison.json",
        "core/facts.json",
        "core/verdict.json",
        "core/evidence/index.json",
        "core/environment.json",
    }
)


def _write(path: Path, value: object) -> None:
    if isinstance(value, bytes):
        contents = value
    elif hasattr(value, "model_dump") or isinstance(value, dict):
        contents = canonical_bytes(value)  # type: ignore[arg-type]
    else:
        raise BundleError("invalid bundle payload")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(contents)
            stream.flush()
            try:
                os.fsync(stream.fileno())
            except OSError:
                pass
    except OSError:
        raise BundleError("unable to write review bundle") from None


def _basename(value: str, fallback: str) -> str:
    parts = [item for item in re.split(r"[\\/]", value) if item]
    return parts[-1] if parts else fallback


def _portable_comparison(comparison: ComparisonResult) -> ComparisonResult:
    before = comparison.before.model_copy(
        update={"path": _basename(comparison.before.path, f"baseline.{comparison.before.format}")}
    )
    after = comparison.after.model_copy(
        update={"path": _basename(comparison.after.path, f"candidate.{comparison.after.format}")}
    )
    return comparison.model_copy(update={"before": before, "after": after})


def _checked_run(
    run: VerificationRun,
    frozen: FrozenPolicy,
) -> tuple[RawVerdict, ContractChangeSet, ComparisonResult]:
    try:
        verdict = RawVerdict.model_validate(run.result)
        facts = ContractChangeSet.model_validate(run.facts)
        comparison = ComparisonResult.model_validate(run.comparison)
    except (AttributeError, ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("invalid verification run") from None
    if (
        verdict.policy_sha256 != frozen.canonical_sha256
        or verdict.baseline_sha256 != facts.baseline_sha256
        or verdict.candidate_sha256 != facts.candidate_sha256
        or comparison.before.sha256 != facts.baseline_sha256
        or comparison.after.sha256 != facts.candidate_sha256
    ):
        raise BundleError("verification run digest binding is invalid")
    return verdict, facts, _portable_comparison(comparison)


def _checked_authorization(
    authorization: PolicyAuthorization | None,
    *,
    policy_digest: str,
) -> PolicyAuthorization:
    try:
        checked = PolicyAuthorization.model_validate(authorization)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("verified bundle requires policy authorization") from None
    if (
        checked.frozen_policy_sha256 != policy_digest
        or checked.signature.purpose != "policy_authorization"
        or checked.signature.canonical_object_sha256 != policy_digest
    ):
        raise BundleError("policy authorization does not match bundle policy")
    return checked


def _checked_event(
    event: SessionOpenedEvent | None,
    *,
    frozen_digest: str,
    baseline_digest: str,
    authorization_digest: str,
) -> SessionOpenedEvent:
    try:
        checked = SessionOpenedEvent.model_validate(event)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("verified bundle requires a session-opened event") from None
    if (
        checked.frozen_policy_sha256 != frozen_digest
        or checked.baseline_sha256 != baseline_digest
        or checked.policy_authorization_sha256 != authorization_digest
        or checked.previous_event_digest != authorization_digest
        or checked.trusted_time
    ):
        raise BundleError("session-opened event does not match bundle")
    return checked


def _payload(root: Path, relative: str) -> BundlePayload:
    path = root / Path(relative)
    return BundlePayload(
        path=relative,
        sha256=canonical_file_digest(path),
        size_bytes=path.stat().st_size,
    )


def _checked_evidence(evidence: Path | None) -> tuple[EvidenceIndex, Path | None]:
    if evidence is None:
        return EvidenceIndex(mode=EvidenceMode.MINIMAL, items=[]), None
    try:
        if evidence.is_symlink() or not evidence.is_dir():
            raise BundleError("evidence directory is invalid")
        root = evidence.resolve(strict=True)
        index_path = root / "index.json"
        if (
            index_path.is_symlink()
            or not index_path.is_file()
            or index_path.stat().st_size > 10 * 1024 * 1024
        ):
            raise BundleError("evidence index is invalid")
        raw = index_path.read_bytes()
        index = EvidenceIndex.model_validate_json(raw)
        if raw != canonical_bytes(index):
            raise BundleError("evidence index is not canonical")
        expected = {item.path for item in index.items}
        if "index.json" in expected:
            raise BundleError("evidence index cannot reference itself")
        actual: set[str] = set()
        for path in root.rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise BundleError("evidence directory contains an unsafe path")
            if path.is_file() and path != index_path:
                actual.add(path.relative_to(root).as_posix())
        if actual != expected:
            raise BundleError("evidence file set does not match index")
        for item in index.items:
            path = root / Path(item.path)
            if (
                path.resolve(strict=True) != path
                or path.stat().st_size != item.size_bytes
                or canonical_file_digest(path) != item.sha256
            ):
                raise BundleError("evidence payload does not match index")
        return index, root
    except BundleError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("evidence directory is invalid") from None


def _copy_evidence(source: Path, destination: Path) -> None:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            output_stream.flush()
            try:
                os.fsync(output_stream.fileno())
            except OSError:
                pass
    except OSError:
        raise BundleError("unable to copy evidence payload") from None


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    for item in path.rglob("*"):
        try:
            item.chmod(stat.S_IWRITE | stat.S_IREAD | (stat.S_IXUSR if item.is_dir() else 0))
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


def _trees_equal(first: Path, second: Path) -> bool:
    first_files = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    second_files = sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
    if first_files != second_files:
        return False
    return all((first / path).read_bytes() == (second / path).read_bytes() for path in first_files)


def write_review_bundle(
    run: VerificationRun,
    frozen: FrozenPolicy,
    *,
    destination: Path,
    assurance: BundleAssurance,
    policy_authorization: PolicyAuthorization | None = None,
    session_event: SessionOpenedEvent | None = None,
    manifest_signer: SigningProvider | None = None,
    evidence: Path | None = None,
) -> Path:
    """Write a new immutable bundle and publish it under its manifest digest."""
    try:
        checked_frozen = validate_frozen_policy_integrity(frozen)
        checked_assurance = BundleAssurance(assurance)
    except (ValueError, TypeError):
        raise BundleError("invalid review bundle input") from None
    if checked_assurance is BundleAssurance.ENTERPRISE:
        raise BundleError("enterprise assurance requires an enterprise identity adapter")
    verdict, facts, comparison = _checked_run(run, checked_frozen)
    evidence_index, evidence_root = _checked_evidence(evidence)
    frozen_digest = frozen_policy_digest(checked_frozen)
    verified = checked_assurance is BundleAssurance.VERIFIED
    if verified and manifest_signer is None:
        raise BundleError("verified bundle requires a manifest signature")
    if not verified and any(
        item is not None for item in (policy_authorization, session_event, manifest_signer)
    ):
        raise BundleError("local bundle cannot contain verified assurance inputs")

    checked_authorization: PolicyAuthorization | None = None
    checked_session_event: SessionOpenedEvent | None = None
    if verified:
        checked_authorization = _checked_authorization(
            policy_authorization,
            policy_digest=frozen_digest,
        )
        authorization_digest = canonical_digest(checked_authorization)
        checked_session_event = _checked_event(
            session_event,
            frozen_digest=frozen_digest,
            baseline_digest=facts.baseline_sha256,
            authorization_digest=authorization_digest,
        )

    try:
        destination.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink() or not destination.is_dir():
            raise BundleError("review bundle destination is invalid")
        destination_root = destination.resolve(strict=True)
    except BundleError:
        raise
    except OSError:
        raise BundleError("review bundle destination is unavailable") from None
    staging = destination_root / f".artifactdiff-bundle.{secrets.token_hex(16)}.tmp"
    try:
        staging.mkdir()
        core = staging / "core"
        events = staging / "events"
        (core / "evidence").mkdir(parents=True)
        events.mkdir()
        _write(core / "policy.json", checked_frozen)
        _write(core / "comparison.json", comparison)
        _write(core / "facts.json", facts)
        _write(core / "verdict.json", verdict)
        _write(core / "evidence" / "index.json", evidence_index)
        for item in evidence_index.items:
            if evidence_root is None:
                raise BundleError("evidence payload root is unavailable")
            copied_evidence = core / "evidence" / Path(item.path)
            _copy_evidence(
                evidence_root / Path(item.path),
                copied_evidence,
            )
            if (
                copied_evidence.stat().st_size != item.size_bytes
                or canonical_file_digest(copied_evidence) != item.sha256
            ):
                raise BundleError("copied evidence payload does not match index")
        environment = {"engine_version": comparison.engine_version}
        _write(core / "environment.json", environment)
        relative_payloads = set(_CORE_FILES)
        relative_payloads.update(f"core/evidence/{item.path}" for item in evidence_index.items)
        event_chain_head: str | None = None
        if checked_authorization is not None and checked_session_event is not None:
            _write(core / "policy.sig", checked_authorization)
            event_path = events / "000001-session-opened.json"
            _write(event_path, checked_session_event)
            relative_payloads.update({"core/policy.sig", "events/000001-session-opened.json"})
            event_chain_head = canonical_file_digest(event_path)

        payloads = [_payload(staging, path) for path in sorted(relative_payloads)]
        manifest = BundleManifest(
            assurance=checked_assurance,
            baseline_sha256=facts.baseline_sha256,
            candidate_sha256=facts.candidate_sha256,
            policy_sha256=frozen_digest,
            raw_verdict_sha256=canonical_digest(verdict),
            event_chain_head=event_chain_head,
            payloads=payloads,
            environment=environment,
        )
        _write(core / "manifest.json", manifest)
        manifest_digest = canonical_digest(manifest)
        if manifest_signer is not None:
            signature = manifest_signer.sign(
                purpose=_MANIFEST_PURPOSE,
                digest=manifest_digest,
                required_role=TrustRole.ARCHIVE_SIGNER,
            )
            try:
                checked_signature = SignatureEnvelope.model_validate(signature)
            except (ValidationError, RecursionError, TypeError, ValueError):
                raise BundleError("invalid manifest signature") from None
            if (
                checked_signature.purpose != _MANIFEST_PURPOSE
                or checked_signature.canonical_object_sha256 != manifest_digest
            ):
                raise BundleError("invalid manifest signature")
            _write(core / "manifest.sig", checked_signature)
        _write(staging / "COMPLETE", manifest_digest.encode("ascii"))

        for path in [*core.rglob("*"), *events.rglob("*")]:
            if path.is_file():
                path.chmod(stat.S_IREAD)
        final = destination_root / manifest_digest
        if final.is_symlink():
            raise BundleError("review bundle destination collision is invalid")
        if final.exists():
            if not final.is_dir() or not _trees_equal(staging, final):
                raise BundleError("review bundle destination collision is invalid")
            return final
        replace_directory(staging, final)
        return final
    except BundleError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("unable to write review bundle") from None
    finally:
        _remove_tree(staging)
