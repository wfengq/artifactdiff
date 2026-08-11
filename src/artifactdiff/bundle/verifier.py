"""Independent, nondisclosing Review Bundle verification."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from artifactdiff.bundle.digests import canonical_bytes, canonical_digest, canonical_file_digest
from artifactdiff.bundle.models import (
    BundleAssurance,
    BundleManifest,
    BundleVerification,
    validate_bundle_path,
)
from artifactdiff.errors import BundleError, PolicyValidationError
from artifactdiff.models import ComparisonResult
from artifactdiff.policy import FrozenPolicy, frozen_policy_digest, validate_frozen_policy_integrity
from artifactdiff.session import SessionOpenedEvent
from artifactdiff.trust import (
    PolicyAuthorization,
    SignatureEnvelope,
    TrustRole,
    TrustStore,
    inspect_signature,
)
from artifactdiff.verification.models import ContractChangeSet, RawVerdict

_LOCAL_CORE = frozenset(
    {
        "core/policy.json",
        "core/comparison.json",
        "core/facts.json",
        "core/verdict.json",
        "core/evidence/index.json",
        "core/environment.json",
    }
)


def _failure(
    errors: list[str],
    *,
    assurance: BundleAssurance = BundleAssurance.LOCAL,
    signature_valid: bool | None = None,
    currently_trusted: bool | None = None,
    event_chain_valid: bool = False,
) -> BundleVerification:
    return BundleVerification(
        valid=False,
        assurance=assurance,
        signature_valid_at_creation=signature_valid,
        currently_trusted=currently_trusted,
        event_chain_valid=event_chain_valid,
        errors=list(dict.fromkeys(errors)),
    )


def _read(path: Path, *, maximum: int = 10 * 1024 * 1024) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise BundleError("bundle_file_invalid")
        return path.read_bytes()
    except BundleError:
        raise
    except OSError:
        raise BundleError("bundle_file_unreadable") from None


def _load_canonical(path: Path, model: type[BaseModel]) -> BaseModel:
    raw = _read(path)
    try:
        value = model.model_validate_json(raw)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("bundle_schema_invalid") from None
    if raw != canonical_bytes(value):
        raise BundleError("bundle_canonical_bytes_invalid")
    return value


def _controlled_file(root: Path, relative: str) -> Path:
    try:
        validate_bundle_path(relative)
        candidate = root / Path(relative)
        resolved = candidate.resolve(strict=True)
    except (OSError, ValueError):
        raise BundleError("bundle_payload_path_invalid") from None
    if candidate.is_symlink() or root not in resolved.parents or resolved != candidate:
        raise BundleError("bundle_payload_path_invalid")
    return candidate


def _signature_status(
    envelope: SignatureEnvelope,
    *,
    purpose: str,
    digest: str,
    role: TrustRole,
    trust_store: TrustStore,
) -> tuple[bool, bool]:
    inspection = inspect_signature(
        envelope,
        purpose=purpose,
        digest=digest,
        required_role=role,
        trust_store=trust_store,
    )
    historically_valid = bool(
        inspection.signature_valid
        and inspection.identity is not None
        and role in inspection.identity.roles
    )
    return historically_valid, inspection.currently_trusted


def _unsigned_event_digest(event: SessionOpenedEvent) -> str:
    payload = event.model_dump(mode="json", exclude={"signature"}, warnings="error")
    return canonical_digest(dict(payload))


def verify_review_bundle(path: Path, *, trust_store: TrustStore) -> BundleVerification:
    """Recompute all public integrity and signature claims from bundle bytes."""
    errors: list[str] = []
    assurance = BundleAssurance.LOCAL
    signature_states: list[bool] = []
    trust_states: list[bool] = []
    event_chain_valid = False
    try:
        if path.is_symlink():
            raise BundleError("bundle_root_invalid")
        root = path.resolve(strict=True)
        if not root.is_dir():
            raise BundleError("bundle_root_invalid")
        for directory in (root / "core", root / "core" / "evidence", root / "events"):
            if directory.is_symlink() or not directory.is_dir() or directory.resolve() != directory:
                raise BundleError("bundle_directory_invalid")
        manifest_value = _load_canonical(root / "core" / "manifest.json", BundleManifest)
        if not isinstance(manifest_value, BundleManifest):
            raise BundleError("bundle_manifest_invalid")
        manifest = manifest_value
        assurance = manifest.assurance
        if assurance is BundleAssurance.ENTERPRISE:
            errors.append("enterprise_assurance_adapter_unavailable")
        manifest_digest = canonical_digest(manifest)
        complete = _read(root / "COMPLETE", maximum=64)
        if complete != manifest_digest.encode("ascii") or root.name != manifest_digest:
            errors.append("bundle_completion_digest_mismatch")

        listed = {item.path for item in manifest.payloads}
        expected = set(_LOCAL_CORE)
        verified = assurance is not BundleAssurance.LOCAL
        if verified:
            expected.update({"core/policy.sig", "events/000001-session-opened.json"})
        if listed != expected:
            errors.append("bundle_payload_set_invalid")
        for item in manifest.payloads:
            try:
                payload_path = _controlled_file(root, item.path)
                if (
                    payload_path.stat().st_size != item.size_bytes
                    or canonical_file_digest(payload_path) != item.sha256
                ):
                    errors.append("payload_digest_mismatch")
            except BundleError as error:
                errors.append(str(error))

        actual_core = {
            path.relative_to(root).as_posix()
            for path in (root / "core").rglob("*")
            if path.is_file()
        }
        allowed_core = {
            *{item for item in expected if item.startswith("core/")},
            "core/manifest.json",
        }
        if verified:
            allowed_core.add("core/manifest.sig")
        if actual_core != allowed_core:
            errors.append("bundle_core_file_set_invalid")

        frozen_value = _load_canonical(root / "core" / "policy.json", FrozenPolicy)
        comparison_value = _load_canonical(root / "core" / "comparison.json", ComparisonResult)
        facts_value = _load_canonical(root / "core" / "facts.json", ContractChangeSet)
        verdict_value = _load_canonical(root / "core" / "verdict.json", RawVerdict)
        if not isinstance(frozen_value, FrozenPolicy):
            raise BundleError("bundle_schema_invalid")
        if not isinstance(comparison_value, ComparisonResult):
            raise BundleError("bundle_schema_invalid")
        if not isinstance(facts_value, ContractChangeSet):
            raise BundleError("bundle_schema_invalid")
        if not isinstance(verdict_value, RawVerdict):
            raise BundleError("bundle_schema_invalid")
        try:
            frozen = validate_frozen_policy_integrity(frozen_value)
        except PolicyValidationError:
            raise BundleError("bundle_policy_invalid") from None
        comparison = comparison_value
        facts = facts_value
        verdict = verdict_value
        if (
            frozen_policy_digest(frozen) != manifest.policy_sha256
            or frozen.canonical_sha256 != verdict.policy_sha256
            or facts.baseline_sha256 != manifest.baseline_sha256
            or facts.candidate_sha256 != manifest.candidate_sha256
            or verdict.baseline_sha256 != manifest.baseline_sha256
            or verdict.candidate_sha256 != manifest.candidate_sha256
            or comparison.before.sha256 != manifest.baseline_sha256
            or comparison.after.sha256 != manifest.candidate_sha256
            or canonical_digest(verdict) != manifest.raw_verdict_sha256
        ):
            errors.append("bundle_cross_digest_invalid")

        environment_raw = _read(root / "core" / "environment.json")
        evidence_raw = _read(root / "core" / "evidence" / "index.json")
        try:
            environment = json.loads(environment_raw)
            evidence = json.loads(evidence_raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BundleError("bundle_schema_invalid") from None
        if (
            environment_raw != canonical_bytes(environment)
            or environment != manifest.environment
            or evidence_raw != canonical_bytes(evidence)
            or evidence != {"items": [], "schema_version": "1.0"}
        ):
            errors.append("bundle_metadata_invalid")

        manifest_signature_path = root / "core" / "manifest.sig"
        if not verified:
            if manifest_signature_path.exists() or manifest.event_chain_head is not None:
                errors.append("local_assurance_claim_invalid")
            event_chain_valid = not any(item.startswith("events/") for item in listed)
        else:
            authorization_value = _load_canonical(root / "core" / "policy.sig", PolicyAuthorization)
            event_value = _load_canonical(
                root / "events" / "000001-session-opened.json",
                SessionOpenedEvent,
            )
            manifest_signature_value = _load_canonical(
                manifest_signature_path,
                SignatureEnvelope,
            )
            if not (
                isinstance(authorization_value, PolicyAuthorization)
                and isinstance(event_value, SessionOpenedEvent)
                and isinstance(manifest_signature_value, SignatureEnvelope)
            ):
                raise BundleError("bundle_signature_schema_invalid")
            authorization = authorization_value
            event = event_value
            manifest_signature = manifest_signature_value
            authorization_digest = canonical_digest(authorization)
            policy_valid, policy_trusted = _signature_status(
                authorization.signature,
                purpose="policy_authorization",
                digest=manifest.policy_sha256,
                role=TrustRole.POLICY_AUTHORIZER,
                trust_store=trust_store,
            )
            event_valid, event_trusted = _signature_status(
                event.signature,
                purpose="session_opened",
                digest=_unsigned_event_digest(event),
                role=TrustRole.ARCHIVE_SIGNER,
                trust_store=trust_store,
            )
            manifest_valid, manifest_trusted = _signature_status(
                manifest_signature,
                purpose="bundle_manifest",
                digest=manifest_digest,
                role=TrustRole.ARCHIVE_SIGNER,
                trust_store=trust_store,
            )
            signature_states.extend((policy_valid, event_valid, manifest_valid))
            trust_states.extend((policy_trusted, event_trusted, manifest_trusted))
            if not all(signature_states):
                errors.append("bundle_signature_invalid")
            event_chain_valid = (
                authorization.frozen_policy_sha256 == manifest.policy_sha256
                and event.frozen_policy_sha256 == manifest.policy_sha256
                and event.baseline_sha256 == manifest.baseline_sha256
                and event.policy_authorization_sha256 == authorization_digest
                and event.previous_event_digest == authorization_digest
                and event.trusted_time is False
                and canonical_digest(event) == manifest.event_chain_head
            )
            if not event_chain_valid:
                errors.append("bundle_event_chain_invalid")
    except BundleError as error:
        errors.append(str(error))
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        errors.append("bundle_verification_failed")
    return BundleVerification(
        valid=not errors,
        assurance=assurance,
        signature_valid_at_creation=(all(signature_states) if signature_states else None),
        currently_trusted=(all(trust_states) if trust_states else None),
        event_chain_valid=event_chain_valid,
        errors=list(dict.fromkeys(errors)),
    )
