"""Deterministic, read-only HTML rendering for verified contract Review Bundles."""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from pydantic import BaseModel, ValidationError

from artifactdiff.bundle.digests import canonical_bytes, canonical_digest
from artifactdiff.bundle.models import BundleAssurance, BundleManifest
from artifactdiff.bundle.verifier import verify_review_bundle
from artifactdiff.errors import BundleError, PolicyValidationError
from artifactdiff.evidence import EvidenceIndex, EvidenceKind
from artifactdiff.policy import (
    ContractPolicy,
    FrozenPolicy,
    frozen_policy_digest,
    validate_frozen_policy_integrity,
)
from artifactdiff.review import (
    ApprovalEvent,
    validate_approval_event_snapshot,
)
from artifactdiff.session import SessionOpenedEvent
from artifactdiff.trust import (
    PolicyAuthorization,
    SignatureEnvelope,
    TrustRole,
    TrustStore,
    inspect_signature,
)
from artifactdiff.verification import RawVerdict

_MAX_CORE_BYTES = 10 * 1024 * 1024
_MAX_EVIDENCE_ITEMS = 1_000
_MAX_IMAGE_BYTES = 5 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 20 * 1024 * 1024
_MAX_EVENT_BYTES = 256 * 1024
_MAX_EVENTS = 1_001


@dataclass(frozen=True, slots=True)
class _CapturedBundle:
    root: Path
    manifest: BundleManifest
    policy: FrozenPolicy
    verdict: RawVerdict
    evidence: EvidenceIndex
    approvals: tuple[ApprovalEvent, ...]
    history: tuple[dict[str, object], ...]
    signatures: tuple[dict[str, object], ...]
    images: tuple[dict[str, str], ...]
    excerpts: tuple[dict[str, str], ...]


def _root(bundle: Path) -> Path:
    try:
        if bundle.is_symlink():
            raise BundleError("contract report bundle path is invalid")
        root = bundle.resolve(strict=True)
        if not root.is_dir():
            raise BundleError("contract report bundle path is invalid")
        return root
    except BundleError:
        raise
    except OSError:
        raise BundleError("contract report bundle path is invalid") from None


def _read(
    root: Path,
    path: Path,
    *,
    maximum: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    descriptor: int | None = None
    try:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise BundleError("contract report bundle file is unsafe")
        path.relative_to(root)
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise BundleError("contract report bundle file exceeds its bound")
        if expected_size is not None and before.st_size != expected_size:
            raise BundleError("contract report bundle file binding is invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        after = path.stat()
    except BundleError:
        raise
    except (OSError, ValueError):
        raise BundleError("contract report bundle file is unsafe") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or len(contents) > maximum
        or len(contents) != opened.st_size
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or (expected_size is not None and len(contents) != expected_size)
        or (expected_sha256 is not None and hashlib.sha256(contents).hexdigest() != expected_sha256)
    ):
        raise BundleError("contract report bundle file changed while reading")
    return contents


def _model(
    root: Path,
    relative: str,
    model: type[BaseModel],
    *,
    maximum: int = _MAX_CORE_BYTES,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> BaseModel:
    raw = _read(
        root,
        root / Path(relative),
        maximum=maximum,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )
    try:
        value = model.model_validate_json(raw)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise BundleError("contract report bundle schema is invalid") from None
    if raw != canonical_bytes(value):
        raise BundleError("contract report bundle bytes are not canonical")
    return value


def _signature(label: str, envelope: SignatureEnvelope) -> dict[str, object]:
    return {
        "label": label,
        "algorithm": envelope.algorithm,
        "identity": envelope.identity,
        "fingerprint": envelope.public_key_fingerprint,
        "purpose": envelope.purpose,
        "object_sha256": envelope.canonical_object_sha256,
        "claimed_signing_time": (
            envelope.claimed_signing_time.isoformat()
            if envelope.claimed_signing_time is not None
            else None
        ),
        "trusted_time": envelope.trusted_time_evidence is not None,
    }


def _media_type(path: str, contents: bytes) -> str | None:
    suffix = Path(path).suffix.casefold()
    if suffix == ".png" and contents.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if suffix in {".jpg", ".jpeg"} and contents.startswith(b"\xff\xd8"):
        return "image/jpeg"
    return None


def _evidence_payloads(
    root: Path, manifest: BundleManifest, index: EvidenceIndex
) -> tuple[tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
    if len(index.items) > _MAX_EVIDENCE_ITEMS:
        raise BundleError("contract report evidence exceeds the bounded model")
    payloads = {item.path: item for item in manifest.payloads}
    images: list[dict[str, str]] = []
    excerpts: list[dict[str, str]] = []
    total = 0
    for item in index.items:
        manifest_item = payloads.get(f"core/evidence/{item.path}")
        if manifest_item is None:
            raise BundleError("contract report evidence binding is invalid")
        if item.kind not in {
            EvidenceKind.EXCERPT,
            EvidenceKind.CHANGED_REGION,
            EvidenceKind.FULL_PAGE,
        }:
            continue
        maximum = _MAX_IMAGE_BYTES if item.kind is not EvidenceKind.EXCERPT else 4 * 1024
        if item.size_bytes > maximum or total + item.size_bytes > _MAX_EVIDENCE_BYTES:
            raise BundleError("contract report evidence exceeds its bound")
        contents = _read(
            root,
            root / "core" / "evidence" / Path(item.path),
            maximum=maximum,
            expected_size=item.size_bytes,
            expected_sha256=item.sha256,
        )
        total += len(contents)
        if item.kind is EvidenceKind.EXCERPT:
            try:
                text = contents.decode("utf-8")
            except UnicodeDecodeError:
                raise BundleError("contract report excerpt is not UTF-8") from None
            if len(text) > 500 or len(text) != item.excerpt_characters:
                raise BundleError("contract report excerpt binding is invalid")
            excerpts.append({"path": item.path, "text": text})
            continue
        media_type = _media_type(item.path, contents)
        if media_type is None:
            raise BundleError("contract report visual evidence type is invalid")
        images.append(
            {
                "path": item.path,
                "kind": item.kind.value,
                "data_url": f"data:{media_type};base64,{base64.b64encode(contents).decode('ascii')}",
            }
        )
    return tuple(images), tuple(excerpts)


def _events(
    root: Path, manifest: BundleManifest
) -> tuple[
    tuple[ApprovalEvent, ...],
    tuple[SessionOpenedEvent, ...],
    tuple[dict[str, object], ...],
    tuple[dict[str, object], ...],
]:
    try:
        paths: list[Path] = []
        for path in (root / "events").iterdir():
            if path.suffix != ".json":
                continue
            paths.append(path)
            if len(paths) > _MAX_EVENTS:
                raise BundleError("contract report event history exceeds the bounded model")
        paths.sort()
    except OSError:
        raise BundleError("contract report event history is unavailable") from None
    manifest_payloads = {item.path: item for item in manifest.payloads}
    approvals: list[ApprovalEvent] = []
    sessions: list[SessionOpenedEvent] = []
    history: list[dict[str, object]] = []
    signatures: list[dict[str, object]] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        expected = manifest_payloads.get(relative)
        if path.name == "000001-session-opened.json":
            if expected is None:
                raise BundleError("contract report session event binding is invalid")
            raw = _read(
                root,
                path,
                maximum=_MAX_EVENT_BYTES,
                expected_size=expected.size_bytes,
                expected_sha256=expected.sha256,
            )
            model: type[SessionOpenedEvent | ApprovalEvent] = SessionOpenedEvent
        elif path.name.endswith("-approval.json"):
            raw = _read(root, path, maximum=_MAX_EVENT_BYTES)
            model = ApprovalEvent
        else:
            raise BundleError("contract report event history is invalid")
        try:
            event = model.model_validate_json(raw)
        except (ValidationError, RecursionError, TypeError, ValueError):
            raise BundleError("contract report event history is invalid") from None
        if raw != canonical_bytes(event):
            raise BundleError("contract report event history is not canonical")
        signatures.append(_signature(f"Event {event.sequence}", event.signature))
        item: dict[str, object] = {
            "sequence": event.sequence,
            "event_type": event.event_type,
            "identity": event.signature.identity,
            "claimed_signing_time": (
                event.signature.claimed_signing_time.isoformat()
                if event.signature.claimed_signing_time is not None
                else None
            ),
        }
        if isinstance(event, ApprovalEvent):
            approvals.append(event)
            item.update(
                finding_id=event.finding_id,
                decision=event.decision.value,
                reason=event.reason,
            )
        else:
            sessions.append(event)
        history.append(item)
    return tuple(approvals), tuple(sessions), tuple(history), tuple(signatures)


def _capture(bundle: Path, trust_store: TrustStore) -> tuple[_CapturedBundle, Any, Any]:
    root = _root(bundle)
    manifest = _model(root, "core/manifest.json", BundleManifest)
    assert isinstance(manifest, BundleManifest)
    manifest_digest = canonical_digest(manifest)
    complete = _read(root, root / "COMPLETE", maximum=64)
    if complete != manifest_digest.encode("ascii") or root.name != manifest_digest:
        raise BundleError("contract report manifest snapshot is not content-addressed")
    payloads = {item.path: item for item in manifest.payloads}

    def captured_model(relative: str, model: type[BaseModel]) -> BaseModel:
        payload = payloads.get(relative)
        if payload is None:
            raise BundleError("contract report manifest payload is missing")
        return _model(
            root,
            relative,
            model,
            expected_size=payload.size_bytes,
            expected_sha256=payload.sha256,
        )

    policy = captured_model("core/policy.json", FrozenPolicy)
    verdict = captured_model("core/verdict.json", RawVerdict)
    evidence = captured_model("core/evidence/index.json", EvidenceIndex)
    assert isinstance(policy, FrozenPolicy)
    assert isinstance(verdict, RawVerdict)
    assert isinstance(evidence, EvidenceIndex)
    try:
        policy = validate_frozen_policy_integrity(policy)
    except PolicyValidationError:
        raise BundleError("contract report policy snapshot is invalid") from None
    if (
        frozen_policy_digest(policy) != manifest.policy_sha256
        or canonical_digest(verdict) != manifest.raw_verdict_sha256
        or verdict.policy_sha256 != policy.canonical_sha256
        or verdict.baseline_sha256 != manifest.baseline_sha256
        or verdict.candidate_sha256 != manifest.candidate_sha256
    ):
        raise BundleError("contract report snapshot cross-digest is invalid")
    if policy.policy.evidence.mode is not evidence.mode:
        raise BundleError("contract report policy and evidence mode do not match")
    first = verify_review_bundle(root, trust_store=trust_store)
    if not first.valid:
        raise BundleError("contract report requires a valid bundle verification")
    images, excerpts = _evidence_payloads(root, manifest, evidence)
    approvals, sessions, history, event_signatures = _events(root, manifest)
    effective = validate_approval_event_snapshot(
        manifest,
        verdict,
        approvals,
        trust_store=trust_store,
        require_current_trust=False,
    )
    signatures: list[dict[str, object]] = []
    for session in sessions:
        session_payload = session.model_dump(mode="json", exclude={"signature"}, warnings="error")
        inspection = inspect_signature(
            session.signature,
            purpose="session_opened",
            digest=canonical_digest(dict(session_payload)),
            required_role=TrustRole.ARCHIVE_SIGNER,
            trust_store=trust_store,
        )
        if not inspection.signature_valid:
            raise BundleError("contract report session signature snapshot is invalid")
    verified_assurance = manifest.assurance is not BundleAssurance.LOCAL
    if verified_assurance:
        authorization = captured_model("core/policy.sig", PolicyAuthorization)
        assert isinstance(authorization, PolicyAuthorization)
        signatures.append(_signature("Policy authorization", authorization.signature))
        policy_inspection = inspect_signature(
            authorization.signature,
            purpose="policy_authorization",
            digest=manifest.policy_sha256,
            required_role=TrustRole.POLICY_AUTHORIZER,
            trust_store=trust_store,
        )
        if not policy_inspection.signature_valid:
            raise BundleError("contract report policy signature snapshot is invalid")
    if verified_assurance:
        envelope = _model(root, "core/manifest.sig", SignatureEnvelope, maximum=64 * 1024)
        assert isinstance(envelope, SignatureEnvelope)
        manifest_inspection = inspect_signature(
            envelope,
            purpose="bundle_manifest",
            digest=manifest_digest,
            required_role=TrustRole.ARCHIVE_SIGNER,
            trust_store=trust_store,
        )
        if not manifest_inspection.signature_valid:
            raise BundleError("contract report manifest signature snapshot is invalid")
        if (
            first.manifest_signer_identity != envelope.identity
            or first.manifest_signer_fingerprint != envelope.public_key_fingerprint
        ):
            raise BundleError("contract report manifest signature attribution changed")
        signatures.append(_signature("Bundle manifest", envelope))
    signatures.extend(event_signatures)
    second = verify_review_bundle(root, trust_store=trust_store)
    if not second.valid or second != first:
        raise BundleError("contract report bundle changed while reading")
    current_approvals, _, _, _ = _events(root, manifest)
    current_effective = validate_approval_event_snapshot(
        manifest,
        verdict,
        current_approvals,
        trust_store=trust_store,
        require_current_trust=False,
    )
    if current_effective.event_chain_head != effective.event_chain_head:
        raise BundleError("contract report bundle changed while reading")
    captured = _CapturedBundle(
        root=root,
        manifest=manifest,
        policy=policy,
        verdict=verdict,
        evidence=evidence,
        approvals=approvals,
        history=history,
        signatures=tuple(signatures),
        images=images,
        excerpts=excerpts,
    )
    return captured, first, effective


def _relaxations(policy: ContractPolicy) -> tuple[dict[str, object], ...]:
    default = ContractPolicy(baseline=policy.baseline)
    values = (
        (
            "protect",
            sorted(item.value for item in default.protect),
            sorted(item.value for item in policy.protect),
        ),
        (
            "metadata.non_business_change",
            default.metadata.non_business_change,
            policy.metadata.non_business_change,
        ),
        (
            "visual.pagination_reflow",
            default.visual.pagination_reflow,
            policy.visual.pagination_reflow,
        ),
        ("visual.on_unavailable", default.visual.on_unavailable, policy.visual.on_unavailable),
        (
            "visual.layout_envelope_padding_points",
            default.visual.layout_envelope_padding_points,
            policy.visual.layout_envelope_padding_points,
        ),
        ("evidence.mode", default.evidence.mode, policy.evidence.mode),
    )
    return tuple(
        {
            "field": field,
            "contract_safe": str(getattr(before, "value", before)),
            "selected": str(getattr(after, "value", after)),
        }
        for field, before, after in values
        if before != after
    )


def _policy_summary(frozen: FrozenPolicy) -> dict[str, object]:
    policy = frozen.policy
    return {
        "profile": policy.profile,
        "profile_version": policy.profile_version,
        "canonical_sha256": frozen.canonical_sha256,
        "evidence_mode": policy.evidence.mode.value,
        "protect": sorted(item.value for item in policy.protect),
        "metadata": policy.metadata.model_dump(mode="json"),
        "visual": policy.visual.model_dump(mode="json"),
        "required_plugins": policy.model_dump(mode="json")["required_plugins"],
        "expect": [
            {
                "id": rule.id,
                "selector": {
                    "clause_label": rule.selector.clause_label,
                    "heading": rule.selector.heading,
                    "ancestor_path": list(rule.selector.ancestor_path),
                    "occurrences": rule.selector.occurrences,
                },
                "operation": rule.operation.model_dump(mode="json"),
            }
            for rule in policy.expect
        ],
        "relaxations": _relaxations(policy),
    }


def write_contract_html(bundle: Path, output: Path, *, trust_store: TrustStore) -> Path:
    """Render a verified Review Bundle as one deterministic, offline, read-only HTML file."""
    captured, verification, effective = _capture(bundle, trust_store)
    environment = Environment(
        loader=PackageLoader("artifactdiff", "reporting"),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default=True),
        undefined=StrictUndefined,
    )
    rendered = environment.get_template("contract_template.html").render(
        manifest=captured.manifest,
        policy=_policy_summary(captured.policy),
        findings=tuple(finding.model_dump(mode="json") for finding in captured.verdict.findings),
        raw_verdict=captured.verdict.outcome.value,
        effective_verdict=effective.model_dump(mode="json"),
        verification=verification.model_dump(mode="json"),
        signatures=captured.signatures,
        history=captured.history,
        evidence_mode=captured.evidence.mode.value,
        excerpts=captured.excerpts,
        images=captured.images,
        visual_unavailable=not captured.images,
        manifest_sha256=canonical_digest(captured.manifest),
    )
    descriptor: int | None = None
    owned_identity: tuple[int, int] | None = None
    published = False
    final: Path | None = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        parent = output.parent.resolve(strict=True)
        if output.parent.is_symlink():
            raise BundleError("contract report output path is unsafe")
        parent_status = parent.stat()
        final = parent / output.name
        if final.is_symlink() or final.exists():
            raise BundleError("contract report output must be new")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(final, flags, 0o600)
        opened = os.fstat(descriptor)
        owned_identity = (opened.st_dev, opened.st_ino)
        contents = rendered.encode("utf-8")
        offset = 0
        while offset < len(contents):
            written = os.write(descriptor, contents[offset:])
            if written <= 0:
                raise BundleError("contract report output publication failed")
            offset += written
        os.fsync(descriptor)
        current_parent = parent.stat()
        if (current_parent.st_dev, current_parent.st_ino) != (
            parent_status.st_dev,
            parent_status.st_ino,
        ) or output.parent.resolve(strict=True) != parent:
            raise BundleError("contract report output parent changed")
        descriptor_status = os.fstat(descriptor)
        path_status = final.stat(follow_symlinks=False)
        if (
            final.is_symlink()
            or (path_status.st_dev, path_status.st_ino) != owned_identity
            or (descriptor_status.st_dev, descriptor_status.st_ino) != owned_identity
            or descriptor_status.st_size != len(contents)
            or path_status.st_size != len(contents)
        ):
            raise BundleError("contract report output publication failed")
        if hashlib.sha256(final.read_bytes()).digest() != hashlib.sha256(contents).digest():
            raise BundleError("contract report output publication failed")
        final_status = final.stat(follow_symlinks=False)
        if (final_status.st_dev, final_status.st_ino) != owned_identity:
            raise BundleError("contract report output publication failed")
        published = True
        return final
    except FileExistsError:
        raise BundleError("contract report output must be new") from None
    except BundleError:
        raise
    except OSError:
        raise BundleError("contract report output publication failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not published and final is not None and owned_identity is not None:
            try:
                status = final.stat(follow_symlinks=False)
                if (
                    not final.is_symlink()
                    and (status.st_dev, status.st_ino) == owned_identity
                    and hashlib.sha256(final.read_bytes()).digest()
                    == hashlib.sha256(contents).digest()
                ):
                    final.unlink()
            except OSError:
                pass
