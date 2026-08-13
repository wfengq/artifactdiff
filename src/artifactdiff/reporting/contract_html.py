"""Deterministic, read-only HTML rendering for verified contract Review Bundles."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from pydantic import BaseModel, ValidationError

from artifactdiff.bundle.digests import canonical_bytes, canonical_digest
from artifactdiff.bundle.models import BundleManifest
from artifactdiff.bundle.verifier import verify_review_bundle
from artifactdiff.errors import BundleError
from artifactdiff.evidence import EvidenceIndex, EvidenceKind
from artifactdiff.policy import ContractPolicy, FrozenPolicy
from artifactdiff.review import (
    ApprovalEvent,
    load_effective_verdict,
    validate_approval_event_snapshot,
)
from artifactdiff.session import SessionOpenedEvent
from artifactdiff.trust import PolicyAuthorization, SignatureEnvelope, TrustStore
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
) -> BaseModel:
    raw = _read(root, root / Path(relative), maximum=maximum)
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
) -> tuple[tuple[ApprovalEvent, ...], tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    try:
        paths = sorted(path for path in (root / "events").iterdir() if path.suffix == ".json")
    except OSError:
        raise BundleError("contract report event history is unavailable") from None
    if len(paths) > _MAX_EVENTS:
        raise BundleError("contract report event history exceeds the bounded model")
    manifest_payloads = {item.path: item for item in manifest.payloads}
    approvals: list[ApprovalEvent] = []
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
        history.append(item)
    return tuple(approvals), tuple(history), tuple(signatures)


def _capture(bundle: Path, trust_store: TrustStore) -> tuple[_CapturedBundle, Any, Any]:
    root = _root(bundle)
    first = verify_review_bundle(root, trust_store=trust_store)
    if not first.valid:
        raise BundleError("contract report requires a valid bundle verification")
    manifest = _model(root, "core/manifest.json", BundleManifest)
    policy = _model(root, "core/policy.json", FrozenPolicy)
    verdict = _model(root, "core/verdict.json", RawVerdict)
    evidence = _model(root, "core/evidence/index.json", EvidenceIndex)
    assert isinstance(manifest, BundleManifest)
    assert isinstance(policy, FrozenPolicy)
    assert isinstance(verdict, RawVerdict)
    assert isinstance(evidence, EvidenceIndex)
    images, excerpts = _evidence_payloads(root, manifest, evidence)
    approvals, history, event_signatures = _events(root, manifest)
    effective = validate_approval_event_snapshot(
        manifest, verdict, approvals, trust_store=trust_store
    )
    signatures: list[dict[str, object]] = []
    policy_signature = root / "core" / "policy.sig"
    if policy_signature.exists():
        authorization = _model(root, "core/policy.sig", PolicyAuthorization)
        assert isinstance(authorization, PolicyAuthorization)
        signatures.append(_signature("Policy authorization", authorization.signature))
    manifest_signature = root / "core" / "manifest.sig"
    if manifest_signature.exists():
        envelope = _model(root, "core/manifest.sig", SignatureEnvelope)
        assert isinstance(envelope, SignatureEnvelope)
        signatures.append(_signature("Bundle manifest", envelope))
    signatures.extend(event_signatures)
    second = verify_review_bundle(root, trust_store=trust_store)
    if not second.valid or second != first:
        raise BundleError("contract report bundle changed while reading")
    current_effective = load_effective_verdict(root, trust_store=trust_store)
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
    try:
        if output.is_symlink() or output.exists():
            raise BundleError("contract report output must be new")
        output.parent.mkdir(parents=True, exist_ok=True)
        parent = output.parent.resolve(strict=True)
        if output.parent.is_symlink():
            raise BundleError("contract report output path is unsafe")
        temporary = parent / f".{output.name}.{secrets.token_hex(8)}.tmp"
        with temporary.open("xb") as stream:
            stream.write(rendered.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(output)
        return output
    except BundleError:
        raise
    except OSError:
        raise BundleError("unable to write contract report") from None
    finally:
        if "temporary" in locals():
            temporary.unlink(missing_ok=True)
