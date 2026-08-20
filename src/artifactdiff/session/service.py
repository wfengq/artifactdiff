"""Policy authorization and fail-closed controlled edit-session services."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import tempfile
from pathlib import Path

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticSerializationError

from artifactdiff.errors import PathSafetyError, PolicyValidationError, SessionError, SignatureError
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.normalize import sha256_file
from artifactdiff.policy import FrozenPolicy, frozen_policy_digest, validate_frozen_policy_integrity
from artifactdiff.policy.canonical import _normalize
from artifactdiff.policy.io import MAX_POLICY_BYTES, _load_json
from artifactdiff.session.models import EditSession, SealedPolicyArtifact, SessionOpenedEvent
from artifactdiff.trust import (
    PolicyAuthorization,
    SigningProvider,
    TrustRole,
    TrustStore,
    verify_signature,
)

_POLICY_PURPOSE = "policy_authorization"
_SESSION_PURPOSE = "session_opened"
_MAX_SESSION_BYTES = MAX_POLICY_BYTES


def _canonical_bytes(value: BaseModel | dict[str, object]) -> bytes:
    try:
        payload = (
            value.model_dump(mode="json", warnings="error")
            if isinstance(value, BaseModel)
            else value
        )
        normalized = _normalize(payload)
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        PolicyValidationError,
        PydanticSerializationError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        raise SessionError("session artifact cannot be canonicalized") from None


def _digest(value: BaseModel | dict[str, object]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _checked_frozen(value: object) -> FrozenPolicy:
    try:
        return validate_frozen_policy_integrity(value)
    except PolicyValidationError:
        raise SessionError("invalid frozen policy") from None


def _checked_authorization(
    value: object,
    *,
    frozen_digest: str,
) -> PolicyAuthorization:
    try:
        authorization = PolicyAuthorization.model_validate(value)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SignatureError("invalid policy authorization") from None
    if (
        authorization.frozen_policy_sha256 != frozen_digest
        or authorization.signature.purpose != _POLICY_PURPOSE
        or authorization.signature.canonical_object_sha256 != frozen_digest
    ):
        raise SignatureError("policy authorization does not match frozen policy")
    return authorization


def authorize_policy(
    frozen: FrozenPolicy,
    *,
    signer: SigningProvider,
) -> PolicyAuthorization:
    """Authorize one canonical frozen policy through the provider boundary."""
    checked = _checked_frozen(frozen)
    digest = frozen_policy_digest(checked)
    signature = signer.sign(
        purpose=_POLICY_PURPOSE,
        digest=digest,
        required_role=TrustRole.POLICY_AUTHORIZER,
    )
    return _checked_authorization(
        PolicyAuthorization(frozen_policy_sha256=digest, signature=signature),
        frozen_digest=digest,
    )


def _checked_sealed(value: object) -> SealedPolicyArtifact:
    try:
        artifact = SealedPolicyArtifact.model_validate(value)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SessionError("invalid sealed policy artifact") from None
    frozen = _checked_frozen(artifact.frozen)
    authorization = artifact.authorization
    if authorization is not None:
        authorization = _checked_authorization(
            authorization,
            frozen_digest=frozen_policy_digest(frozen),
        )
    try:
        return SealedPolicyArtifact(frozen=frozen, authorization=authorization)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SessionError("invalid sealed policy artifact") from None


def _write_canonical(path: Path, value: BaseModel) -> None:
    contents = _canonical_bytes(value)
    if len(contents) > _MAX_SESSION_BYTES:
        raise SessionError("session artifact exceeds 1 MiB limit")
    try:
        with path.open("xb") as stream:
            stream.write(contents)
            stream.flush()
            try:
                os.fsync(stream.fileno())
            except OSError:
                pass
    except FileExistsError:
        raise SessionError("session artifact already exists") from None
    except OSError:
        raise SessionError("unable to write session artifact") from None


def write_sealed_policy(
    artifact: SealedPolicyArtifact, path: Path, *, overwrite: bool = True
) -> Path:
    """Atomically write frozen policy and optional authorization without assurance."""
    checked = _checked_sealed(artifact)
    if path.suffix.casefold() != ".json":
        raise SessionError("unsupported sealed policy format")
    contents = _canonical_bytes(checked)
    if len(contents) > _MAX_SESSION_BYTES:
        raise SessionError("sealed policy artifact exceeds 1 MiB limit")
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(contents)
            stream.flush()
            try:
                os.fsync(stream.fileno())
            except OSError:
                pass
        if overwrite:
            temporary.replace(path)
        else:
            os.link(temporary, path, follow_symlinks=False)
    except OSError:
        raise SessionError("unable to write sealed policy artifact") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return path


def _read_bounded(path: Path, *, label: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_SESSION_BYTES:
            raise SessionError(f"invalid {label}")
        raw = path.read_bytes()
    except SessionError:
        raise
    except OSError:
        raise SessionError(f"unable to read {label}") from None
    if len(raw) > _MAX_SESSION_BYTES:
        raise SessionError(f"invalid {label}")
    return raw


def load_sealed_policy(path: Path) -> SealedPolicyArtifact:
    """Load and structurally validate a bounded canonical sealed-policy JSON file."""
    if path.suffix.casefold() != ".json":
        raise SessionError("unsupported sealed policy format")
    raw = _read_bounded(path, label="sealed policy artifact")
    try:
        payload = _load_json(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        artifact = _checked_sealed(payload)
    except SessionError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        raise SessionError("invalid sealed policy artifact") from None
    if raw != _canonical_bytes(artifact):
        raise SessionError("sealed policy artifact is not canonical")
    return artifact


def _authorization_digest(authorization: PolicyAuthorization) -> str:
    return _digest(authorization)


def _event_payload(event: SessionOpenedEvent) -> dict[str, object]:
    payload = event.model_dump(mode="json", exclude={"signature"}, warnings="error")
    return dict(payload)


def _session_id(policy_digest: str, baseline_digest: str, nonce: bytes) -> str:
    return hashlib.sha256(
        b"ArtifactDiff-Session-v1\0"
        + bytes.fromhex(policy_digest)
        + bytes.fromhex(baseline_digest)
        + nonce
    ).hexdigest()


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    for item in path.rglob("*"):
        try:
            item.chmod(stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


def _after_stage_write(_stage: str) -> None:
    """Test seam for exercising cleanup after durable write boundaries."""


def open_verified_edit_session(
    baseline: Path,
    frozen: FrozenPolicy,
    authorization: PolicyAuthorization,
    *,
    root: Path,
    trust_store: TrustStore,
    session_signer: SigningProvider,
    path_policy: PathPolicy,
) -> EditSession:
    """Create a controlled candidate only after policy authorization verifies."""
    checked_frozen = _checked_frozen(frozen)
    frozen_digest = frozen_policy_digest(checked_frozen)
    checked_authorization = _checked_authorization(
        authorization,
        frozen_digest=frozen_digest,
    )
    verify_signature(
        checked_authorization.signature,
        purpose=_POLICY_PURPOSE,
        digest=frozen_digest,
        required_role=TrustRole.POLICY_AUTHORIZER,
        trust_store=trust_store,
    )

    resolved_baseline = path_policy.resolve_input(baseline)
    if resolved_baseline.suffix.casefold().lstrip(".") != checked_frozen.policy.baseline.format:
        raise SessionError("baseline format does not match frozen policy")
    expected_baseline_digest = checked_frozen.policy.baseline.sha256
    try:
        observed_baseline_digest = sha256_file(resolved_baseline)
    except OSError:
        raise SessionError("unable to read baseline") from None
    if observed_baseline_digest != expected_baseline_digest:
        raise SessionError("baseline does not match frozen policy")

    nonce = secrets.token_bytes(32)
    identifier = _session_id(frozen_digest, expected_baseline_digest, nonce)
    authorization_digest = _authorization_digest(checked_authorization)
    event_fields: dict[str, object] = {
        "schema_version": "1.0",
        "event_type": "session_opened",
        "sequence": 1,
        "session_id": identifier,
        "frozen_policy_sha256": frozen_digest,
        "baseline_sha256": observed_baseline_digest,
        "policy_authorization_sha256": authorization_digest,
        "previous_event_digest": authorization_digest,
        "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
        "chronology": "artifactdiff_controlled_session",
        "trusted_time": False,
    }
    event_digest = _digest(event_fields)
    event_signature = session_signer.sign(
        purpose=_SESSION_PURPOSE,
        digest=event_digest,
        required_role=TrustRole.ARCHIVE_SIGNER,
    )
    verify_signature(
        event_signature,
        purpose=_SESSION_PURPOSE,
        digest=event_digest,
        required_role=TrustRole.ARCHIVE_SIGNER,
        trust_store=trust_store,
    )
    event = SessionOpenedEvent.model_validate({**event_fields, "signature": event_signature})

    resolved_root = path_policy.resolve_output(root)
    final = path_policy.resolve_output(resolved_root / "sessions" / identifier)
    staging = path_policy.resolve_output(final.parent / f".{identifier}.{secrets.token_hex(8)}.tmp")
    if final.exists() or staging.exists():
        raise SessionError("edit session destination already exists")

    try:
        staging.mkdir()
        policy_path = staging / "policy.json"
        _write_canonical(
            policy_path,
            SealedPolicyArtifact(
                frozen=checked_frozen,
                authorization=checked_authorization,
            ),
        )
        _after_stage_write("policy")

        baseline_dir = staging / "baseline"
        candidate_dir = staging / "candidate"
        events_dir = staging / "events"
        baseline_dir.mkdir()
        candidate_dir.mkdir()
        events_dir.mkdir()
        baseline_snapshot = baseline_dir / resolved_baseline.name
        candidate = candidate_dir / resolved_baseline.name
        shutil.copyfile(resolved_baseline, baseline_snapshot)
        _after_stage_write("baseline")
        snapshot_baseline_digest = sha256_file(baseline_snapshot)
        if snapshot_baseline_digest != expected_baseline_digest:
            raise SessionError("baseline does not match frozen policy")
        shutil.copyfile(baseline_snapshot, candidate)
        _after_stage_write("candidate")

        _write_canonical(events_dir / "000001-session-opened.json", event)
        _after_stage_write("event")

        final_policy = final / "policy.json"
        final_baseline = final / "baseline" / resolved_baseline.name
        final_candidate = final / "candidate" / resolved_baseline.name
        session = EditSession(
            session_id=identifier,
            root_path=final,
            policy_path=final_policy,
            baseline_snapshot_path=final_baseline,
            candidate_path=final_candidate,
            frozen_policy_sha256=frozen_digest,
            baseline_sha256=snapshot_baseline_digest,
            policy_authorization_sha256=authorization_digest,
            events=[event],
        )
        _write_canonical(staging / "session.json", session)
        _after_stage_write("session")
        baseline_snapshot.chmod(stat.S_IREAD)
        if sha256_file(baseline_snapshot) != snapshot_baseline_digest:
            raise SessionError("baseline snapshot changed before session publication")
        staging.replace(final)
        return session
    except (PathSafetyError, SignatureError, SessionError):
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise SessionError("unable to create verified edit session") from None
    finally:
        _remove_tree(staging)


def _load_model(path: Path, model: type[BaseModel], *, label: str) -> BaseModel:
    raw = _read_bounded(path, label=label)
    try:
        value = model.model_validate_json(raw)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise SessionError(f"invalid {label}") from None
    if raw != _canonical_bytes(value):
        raise SessionError(f"{label} is not canonical")
    return value


def load_edit_session(path: Path, *, trust_store: TrustStore) -> EditSession:
    """Independently validate an on-disk controlled edit session."""
    try:
        if path.is_symlink():
            raise SessionError("invalid edit session path")
        root = path.resolve(strict=True)
    except SessionError:
        raise
    except OSError:
        raise SessionError("invalid edit session path") from None
    if not root.is_dir() or root.name.startswith("."):
        raise SessionError("invalid edit session path")
    loaded = _load_model(root / "session.json", EditSession, label="edit session")
    if not isinstance(loaded, EditSession):
        raise SessionError("invalid edit session")
    session = loaded
    if session.root_path != root or session.root_path.name != session.session_id:
        raise SessionError("edit session path does not match session identity")
    expected_policy = root / "policy.json"
    expected_baseline = root / "baseline" / session.baseline_snapshot_path.name
    expected_candidate = root / "candidate" / session.candidate_path.name
    controlled_directories = (root / "baseline", root / "candidate", root / "events")
    if (
        session.policy_path != expected_policy
        or session.baseline_snapshot_path != expected_baseline
        or session.candidate_path != expected_candidate
        or expected_baseline.name != expected_candidate.name
    ):
        raise SessionError("edit session contains invalid controlled paths")
    for directory in controlled_directories:
        try:
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or directory.resolve(strict=True) != directory
            ):
                raise SessionError("edit session controlled directory is invalid")
        except OSError:
            raise SessionError("edit session controlled directory is invalid") from None
    for controlled in (expected_policy, expected_baseline, expected_candidate):
        try:
            resolved_controlled = controlled.resolve(strict=True)
        except OSError:
            raise SessionError("edit session controlled file is unavailable") from None
        if (
            controlled.is_symlink()
            or not controlled.is_file()
            or resolved_controlled != controlled
            or root not in resolved_controlled.parents
        ):
            raise SessionError("edit session controlled file is unavailable")
    if expected_baseline.stat().st_mode & stat.S_IWUSR:
        raise SessionError("edit session baseline snapshot is writable")

    artifact = load_sealed_policy(expected_policy)
    if artifact.authorization is None:
        raise SessionError("verified edit session lacks policy authorization")
    frozen_digest = frozen_policy_digest(artifact.frozen)
    authorization = _checked_authorization(
        artifact.authorization,
        frozen_digest=frozen_digest,
    )
    verify_signature(
        authorization.signature,
        purpose=_POLICY_PURPOSE,
        digest=frozen_digest,
        required_role=TrustRole.POLICY_AUTHORIZER,
        trust_store=trust_store,
    )
    authorization_digest = _authorization_digest(authorization)
    if (
        frozen_digest != session.frozen_policy_sha256
        or authorization_digest != session.policy_authorization_sha256
        or sha256_file(expected_baseline) != session.baseline_sha256
    ):
        raise SessionError("edit session digest binding is invalid")

    event_value = _load_model(
        root / "events" / "000001-session-opened.json",
        SessionOpenedEvent,
        label="session-opened event",
    )
    if not isinstance(event_value, SessionOpenedEvent) or event_value != session.events[0]:
        raise SessionError("session-opened event does not match session")
    event = event_value
    if event.previous_event_digest != authorization_digest:
        raise SessionError("session event chain is invalid")
    verify_signature(
        event.signature,
        purpose=_SESSION_PURPOSE,
        digest=_digest(_event_payload(event)),
        required_role=TrustRole.ARCHIVE_SIGNER,
        trust_store=trust_store,
    )
    return session


def claim_verified_candidate(candidate: Path, session: EditSession) -> Path:
    """Require the exact writable candidate created by one controlled session."""
    error = "verified candidates must originate in an ArtifactDiff edit session"
    try:
        checked = EditSession.model_validate(session)
        if candidate.is_symlink() or checked.candidate_path.is_symlink():
            raise SessionError(error)
        resolved_candidate = candidate.resolve(strict=True)
        expected = checked.candidate_path.resolve(strict=True)
        root = checked.root_path.resolve(strict=True)
    except SessionError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise SessionError(error) from None
    if (
        resolved_candidate != expected
        or not expected.is_file()
        or not (expected == root or root in expected.parents)
    ):
        raise SessionError(error)
    return expected
