"""Append-only human finding approvals and effective verdict recomputation."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from artifactdiff.bundle.digests import canonical_bytes, canonical_digest
from artifactdiff.bundle.events import signed_event_digest, unsigned_approval_digest
from artifactdiff.bundle.models import BundleManifest
from artifactdiff.bundle.verifier import verify_review_bundle
from artifactdiff.errors import ApprovalError, SignatureError
from artifactdiff.review.models import ApprovalDecision, ApprovalEvent, EffectiveVerdict
from artifactdiff.trust import (
    SigningProvider,
    TrustRole,
    TrustStore,
    inspect_signature,
    verify_signature,
)
from artifactdiff.verification import Finding, FindingOutcome, RawVerdict

_APPROVAL_FILE = re.compile(r"^(\d{6})-approval\.json$")
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _root(path: Path) -> Path:
    try:
        if path.is_symlink():
            raise ApprovalError("invalid review bundle path")
        root = path.resolve(strict=True)
    except ApprovalError:
        raise
    except OSError:
        raise ApprovalError("invalid review bundle path") from None
    if not root.is_dir():
        raise ApprovalError("invalid review bundle path")
    return root


def _load_model(path: Path, model: type[_ModelT]) -> _ModelT:
    try:
        if path.is_symlink() or not path.is_file():
            raise ApprovalError("invalid review bundle artifact")
        raw = path.read_bytes()
        value = model.model_validate_json(raw)
    except ApprovalError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise ApprovalError("invalid review bundle artifact") from None
    if raw != canonical_bytes(value):
        raise ApprovalError("review bundle artifact is not canonical")
    return value


def _manifest(root: Path) -> BundleManifest:
    value = _load_model(root / "core" / "manifest.json", BundleManifest)
    if not isinstance(value, BundleManifest):
        raise ApprovalError("invalid review bundle manifest")
    return value


def _verdict(root: Path) -> RawVerdict:
    value = _load_model(root / "core" / "verdict.json", RawVerdict)
    if not isinstance(value, RawVerdict):
        raise ApprovalError("invalid review bundle verdict")
    return value


def _approval_events(root: Path) -> list[ApprovalEvent]:
    events: list[ApprovalEvent] = []
    try:
        paths = sorted(
            path for path in (root / "events").iterdir() if _APPROVAL_FILE.fullmatch(path.name)
        )
    except OSError:
        raise ApprovalError("unable to read approval events") from None
    for path in paths:
        value = _load_model(path, ApprovalEvent)
        if not isinstance(value, ApprovalEvent):
            raise ApprovalError("invalid approval event")
        events.append(value)
    return events


def list_findings(bundle: Path) -> list[Finding]:
    """List immutable raw findings without changing their outcome."""
    return list(_verdict(_root(bundle)).findings)


def compute_effective_verdict(
    raw: RawVerdict,
    events: Sequence[ApprovalEvent],
    *,
    trust_store: TrustStore,
    verification_digest: str,
    require_current_trust: bool = True,
) -> EffectiveVerdict:
    """Validate signed decisions and recompute the fail-closed effective outcome."""
    try:
        verdict = RawVerdict.model_validate(raw)
        checked_events = [ApprovalEvent.model_validate(event) for event in events]
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise ApprovalError("invalid approval inputs") from None
    findings = {item.id: item for item in verdict.findings}
    decided: dict[str, ApprovalDecision] = {}
    previous: str | None = None
    prior_sequence: int | None = None
    for event in checked_events:
        if event.verification_digest != verification_digest:
            raise ApprovalError("approval event belongs to another verification")
        if prior_sequence is not None and event.sequence != prior_sequence + 1:
            raise ApprovalError("approval event sequence is invalid")
        if previous is not None and event.previous_event_digest != previous:
            raise ApprovalError("approval event chain is invalid")
        finding = findings.get(event.finding_id)
        if (
            finding is None
            or finding.outcome is not FindingOutcome.REVIEW
            or not finding.approvable
        ):
            raise ApprovalError("approval event references an ineligible finding")
        if event.finding_id in decided:
            raise ApprovalError("finding already has a decision")
        if require_current_trust:
            identity = verify_signature(
                event.signature,
                purpose="finding_approval",
                digest=unsigned_approval_digest(event),
                required_role=TrustRole.FINDING_APPROVER,
                trust_store=trust_store,
            )
        else:
            inspection = inspect_signature(
                event.signature,
                purpose="finding_approval",
                digest=unsigned_approval_digest(event),
                required_role=TrustRole.FINDING_APPROVER,
                trust_store=trust_store,
            )
            if (
                not inspection.signature_valid
                or inspection.identity is None
                or TrustRole.FINDING_APPROVER not in inspection.identity.roles
            ):
                raise SignatureError("approval signature is historically invalid")
            identity = inspection.identity
        if identity.subject_type != "human":
            raise ApprovalError("finding approvals require a human identity")
        decided[event.finding_id] = event.decision
        previous = signed_event_digest(event)
        prior_sequence = event.sequence

    approved = sorted(
        finding_id
        for finding_id, decision in decided.items()
        if decision is ApprovalDecision.APPROVED
    )
    fail_ids = sorted(item.id for item in verdict.findings if item.outcome is FindingOutcome.FAIL)
    remaining = sorted(
        item.id
        for item in verdict.findings
        if item.outcome is FindingOutcome.REVIEW and item.id not in approved
    )
    outcome = (
        FindingOutcome.FAIL
        if fail_ids
        else FindingOutcome.REVIEW
        if remaining
        else FindingOutcome.PASS
    )
    return EffectiveVerdict(
        raw_outcome=verdict.outcome,
        outcome=outcome,
        approved_finding_ids=approved,
        remaining_review_finding_ids=remaining,
        fail_finding_ids=fail_ids,
        event_chain_head=previous or verification_digest,
    )


def validate_approval_event_snapshot(
    manifest: BundleManifest,
    raw: RawVerdict,
    events: Sequence[ApprovalEvent],
    *,
    trust_store: TrustStore,
    require_current_trust: bool = True,
) -> EffectiveVerdict:
    """Validate the exact in-memory approval bytes as one manifest-bound chain."""
    manifest_digest = canonical_digest(manifest)
    expected_sequence = 2 if manifest.event_chain_head is not None else 1
    expected_previous = manifest.event_chain_head or manifest_digest
    for event in events:
        if event.sequence != expected_sequence or event.previous_event_digest != expected_previous:
            raise ApprovalError("approval event chain is invalid")
        expected_sequence += 1
        expected_previous = signed_event_digest(event)
    try:
        effective = compute_effective_verdict(
            raw,
            events,
            trust_store=trust_store,
            verification_digest=manifest_digest,
            require_current_trust=require_current_trust,
        )
    except SignatureError:
        raise ApprovalError("approval event signature is invalid") from None
    expected_head = expected_previous
    if effective.event_chain_head != expected_head:
        effective = effective.model_copy(update={"event_chain_head": expected_head})
    return effective


def load_effective_verdict(bundle: Path, *, trust_store: TrustStore) -> EffectiveVerdict:
    root = _root(bundle)
    verification = verify_review_bundle(root, trust_store=trust_store)
    if not verification.valid:
        raise ApprovalError("review bundle verification failed")
    manifest = _manifest(root)
    events = _approval_events(root)
    return validate_approval_event_snapshot(
        manifest,
        _verdict(root),
        events,
        trust_store=trust_store,
    )


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _reclaim_stale_lock(path: Path) -> bool:
    try:
        if path.is_symlink():
            return False
        status = path.stat()
        if time.time() - status.st_mtime <= 30:
            return False
        raw = path.read_bytes()
        if len(raw) > 512:
            return False
        payload = json.loads(raw)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"nonce", "pid"}
            or not isinstance(payload["pid"], int)
            or isinstance(payload["pid"], bool)
            or not isinstance(payload["nonce"], str)
            or re.fullmatch(r"[0-9a-f]{32}", payload["nonce"]) is None
            or _process_is_alive(payload["pid"])
        ):
            return False
        if path.read_bytes() != raw or path.stat().st_mtime_ns != status.st_mtime_ns:
            return False
        path.unlink()
        return True
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return False


def _acquire_lock(path: Path) -> tuple[int, bytes]:
    payload = json.dumps(
        {"pid": os.getpid(), "nonce": secrets.token_hex(16)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    for attempt in range(2):
        descriptor: int | None = None
        created = False
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            os.write(descriptor, payload)
            os.fsync(descriptor)
            return descriptor, payload
        except FileExistsError:
            if attempt == 0 and _reclaim_stale_lock(path):
                continue
            raise ApprovalError("approval events are locked") from None
        except OSError:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if created:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise ApprovalError("unable to lock approval events") from None
    raise ApprovalError("approval events are locked")


def approve_finding(
    bundle: Path,
    finding_id: str,
    reason: str,
    *,
    signer: SigningProvider,
    trust_store: TrustStore,
) -> ApprovalEvent:
    """Append one human-signed finding decision without rewriting bundle core."""
    root = _root(bundle)
    verification = verify_review_bundle(root, trust_store=trust_store)
    if not verification.valid or verification.currently_trusted is False:
        raise ApprovalError("review bundle verification failed")
    findings = {item.id: item for item in _verdict(root).findings}
    finding = findings.get(finding_id)
    if finding is None:
        raise ApprovalError("finding does not exist")
    if finding.outcome is FindingOutcome.FAIL:
        raise ApprovalError("fail findings cannot be approved")
    if finding.outcome is not FindingOutcome.REVIEW or not finding.approvable:
        raise ApprovalError("finding is not approvable")

    lock_path = root / "events" / ".events.lock"
    descriptor: int | None = None
    lock_owned = False
    temporary: Path | None = None
    try:
        descriptor, _ = _acquire_lock(lock_path)
        lock_owned = True
        os.close(descriptor)
        descriptor = None
        verification = verify_review_bundle(root, trust_store=trust_store)
        if not verification.valid:
            raise ApprovalError("review bundle verification failed")
        manifest = _manifest(root)
        manifest_digest = canonical_digest(manifest)
        existing = _approval_events(root)
        if any(event.finding_id == finding_id for event in existing):
            raise ApprovalError("finding already has a decision")
        sequence = (
            (existing[-1].sequence + 1) if existing else (2 if manifest.event_chain_head else 1)
        )
        previous = (
            signed_event_digest(existing[-1])
            if existing
            else manifest.event_chain_head or manifest_digest
        )
        unsigned = {
            "schema_version": "1.0",
            "event_type": "finding_decision",
            "sequence": sequence,
            "verification_digest": manifest_digest,
            "previous_event_digest": previous,
            "finding_id": finding_id,
            "decision": ApprovalDecision.APPROVED,
            "reason": reason,
        }
        digest = canonical_digest(unsigned)
        signature = signer.sign(
            purpose="finding_approval",
            digest=digest,
            required_role=TrustRole.FINDING_APPROVER,
        )
        event = ApprovalEvent.model_validate({**unsigned, "signature": signature})
        identity = verify_signature(
            event.signature,
            purpose="finding_approval",
            digest=unsigned_approval_digest(event),
            required_role=TrustRole.FINDING_APPROVER,
            trust_store=trust_store,
        )
        if identity.subject_type != "human":
            raise ApprovalError("finding approvals require a human identity")
        destination = root / "events" / f"{sequence:06d}-approval.json"
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
        with temporary.open("xb") as stream:
            stream.write(canonical_bytes(event))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
        destination.chmod(stat.S_IREAD)
        return event
    except ApprovalError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise ApprovalError("unable to append approval event") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if lock_owned:
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass
