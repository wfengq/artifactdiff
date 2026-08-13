"""Authenticated, bounded JSON views for one local contract review task."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from artifactdiff.application import ArtifactDiffApplication, PolicyValidationResult
from artifactdiff.bundle import BundleManifest, BundleVerification
from artifactdiff.bundle.digests import canonical_bytes
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import ApprovalError, ArtifactDiffError, PolicyValidationError
from artifactdiff.evidence import EvidenceIndex, EvidenceKind
from artifactdiff.policy import (
    ContractPolicy,
    EvidencePolicy,
    MetadataPolicy,
    VisualPolicy,
    canonical_policy_bytes,
    policy_digest,
)
from artifactdiff.policy.models import PolicyPluginRequirement
from artifactdiff.review import ApprovalEvent
from artifactdiff.review_web.signing_provider import ReviewSigningProvider
from artifactdiff.session import SealedPolicyArtifact, SessionOpenedEvent, write_sealed_policy
from artifactdiff.verification import Finding, FindingOutcome, RawVerdict


class _ViewModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SelectorRequest(_ViewModel):
    clause_label: str = Field(max_length=256)
    heading: str = Field(max_length=512)
    ancestor_path: list[Annotated[str, Field(max_length=512)]] = Field(
        default_factory=list, max_length=16
    )
    anchor: str = Field(min_length=1, max_length=4096)


class PolicyDraftRequest(_ViewModel):
    rule_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    selector: SelectorRequest
    before: str = Field(min_length=1, max_length=10_000)
    after: str = Field(min_length=1, max_length=10_000)
    protect: list[str] | None = Field(default=None, max_length=32)
    metadata: MetadataPolicy | None = None
    visual: VisualPolicy | None = None
    evidence: EvidencePolicy | None = None
    required_plugins: dict[str, PolicyPluginRequirement] | None = Field(default=None, max_length=32)


class PolicySealRequest(_ViewModel):
    assurance: Literal["local", "verified"] = "local"


class ApprovalRequest(_ViewModel):
    finding_id: str = Field(pattern=r"^finding-[0-9a-f]{24}$")
    reason: str = Field(min_length=3, max_length=2000)


@dataclass(slots=True)
class ReviewViews:
    application: ArtifactDiffApplication
    mode: str
    target_path: Path
    signing_provider: ReviewSigningProvider | None
    output_path: Path | None = None
    _draft: ContractPolicy | None = None

    def policy_overview(self) -> dict[str, object]:
        self._require_mode("policy")
        inspected = self.application.inspect_contract(self.target_path, max_clauses=100)
        source = inspected.get("source", {})
        if not isinstance(source, dict):
            source = {}
        baseline = ContractPolicy.model_validate(
            {"baseline": {"sha256": source.get("sha256"), "format": source.get("format")}}
        )
        clauses = []
        raw_clauses = inspected.get("clauses", [])
        if not isinstance(raw_clauses, list):
            raw_clauses = []
        for value in raw_clauses:
            if not isinstance(value, dict):
                continue
            clauses.append(
                {
                    "id": value.get("id"),
                    "clause_label": (value.get("label") or {}).get("printed"),
                    "heading": value.get("heading"),
                    "ancestor_path": value.get("ancestor_path", []),
                }
            )
        return {
            "state": "policy-draft",
            "baseline": {
                "sha256": source.get("sha256"),
                "format": source.get("format"),
            },
            "clauses": clauses,
            "truncated": inspected.get("truncated_clauses", False),
            "assurance": "local",
            "contract_safe": {
                "protect": sorted(item.value for item in baseline.protect),
                "metadata": baseline.metadata.model_dump(mode="json"),
                "visual": baseline.visual.model_dump(mode="json"),
                "evidence": baseline.evidence.model_dump(mode="json"),
                "required_plugins": {},
            },
        }

    def draft_policy(self, payload: object) -> dict[str, object]:
        self._require_mode("policy")
        request = PolicyDraftRequest.model_validate(payload)
        drafted = self.application.draft_policy(
            self.target_path,
            ClauseSelector.model_validate(request.selector.model_dump(mode="python")),
            before=request.before,
            after=request.after,
            rule_id=request.rule_id,
        )
        policy_payload = drafted.model_dump(mode="json", warnings="error")
        for field in ("protect", "metadata", "visual", "evidence", "required_plugins"):
            value = getattr(request, field)
            if value is not None:
                policy_payload[field] = (
                    value.model_dump(mode="json", warnings="error")
                    if isinstance(value, BaseModel)
                    else value
                )
        policy = ContractPolicy.model_validate(policy_payload)
        self._draft = policy
        checked = self._validate_through_facade(policy)
        return {
            "state": "policy-ready",
            "policy": policy.model_dump(mode="json"),
            "summary": _policy_summary(policy, resolved_clause_id=checked.resolved_clause_id),
        }

    def seal_policy(self, payload: object) -> dict[str, object]:
        self._require_mode("policy")
        request = PolicySealRequest.model_validate(payload)
        if self._draft is None:
            raise PolicyValidationError("policy must be drafted before sealing")
        with TemporaryDirectory(prefix="artifactdiff-review-policy-") as temporary:
            root = Path(temporary)
            policy_path = self.application.write_policy(self._draft, root / "policy.json")
            sealed = self.application.seal_local_policy_artifact(
                self.target_path, policy_path, root / "sealed.json"
            ).artifact
        authorization = None
        if request.assurance == "verified":
            if self.signing_provider is None:
                raise PolicyValidationError("verified assurance requires a signing provider")
            authorization = self.signing_provider.sign_policy(sealed.frozen)
        artifact = SealedPolicyArtifact(frozen=sealed.frozen, authorization=authorization)
        if self.output_path is None:
            raise PolicyValidationError("sealed policy output is not configured")
        write_sealed_policy(artifact, self.output_path)
        return {
            "state": "policy-ready",
            "assurance": request.assurance,
            "artifact": artifact.model_dump(mode="json"),
            "output": str(self.output_path.resolve()),
        }

    def bundle_overview(self, event_cursor: int = 0, event_limit: int = 100) -> dict[str, object]:
        self._require_mode("bundle")
        verification = self._verified_bundle()
        event_history, snapshot_head = _event_history(
            self.application,
            self.target_path,
            cursor=event_cursor,
            limit=event_limit,
        )
        effective = self.application.effective_verdict(self.target_path)
        if effective.event_chain_head != snapshot_head:
            raise ApprovalError("review bundle changed while reading event history")
        verification = self._verified_bundle()
        return {
            "state": f"bundle-{effective.outcome.value}",
            "assurance": verification.assurance.value,
            "raw_verdict": effective.raw_outcome.value,
            "effective_verdict": effective.model_dump(mode="json"),
            "signature_status": {
                "valid_at_creation": verification.signature_valid_at_creation,
                "currently_trusted": verification.currently_trusted,
                "event_chain_valid": verification.event_chain_valid,
            },
            "event_history": event_history,
        }

    def list_findings(self, cursor: int, limit: int) -> dict[str, object]:
        self._require_mode("bundle")
        self._verified_bundle()
        if cursor < 0 or limit < 1 or limit > 100:
            raise ApprovalError("invalid finding page")
        findings = self.application.list_findings(self.target_path)
        page = findings[cursor : cursor + limit]
        next_cursor = cursor + len(page) if cursor + len(page) < len(findings) else None
        return {
            "items": [_finding_payload(item) for item in page],
            "cursor": cursor,
            "next_cursor": next_cursor,
            "total": len(findings),
        }

    def finding(self, finding_id: str) -> dict[str, object]:
        self._require_mode("bundle")
        self._verified_bundle()
        finding = self.application.get_finding(self.target_path, finding_id)
        payload = _finding_payload(finding)
        payload["approval_enabled"] = (
            finding.outcome is FindingOutcome.REVIEW and finding.approvable
        )
        payload["page_crops"] = _crop_payloads(self.target_path, finding)
        self._verified_bundle()
        return payload

    def approve(self, payload: object) -> dict[str, object]:
        self._require_mode("bundle")
        self._verified_bundle()
        request = ApprovalRequest.model_validate(payload)
        finding = self.application.get_finding(self.target_path, request.finding_id)
        if finding.outcome is not FindingOutcome.REVIEW or not finding.approvable:
            raise ApprovalError("finding is not approvable")
        if self.signing_provider is None:
            raise ApprovalError("approval signing provider is unavailable")
        event = self.signing_provider.sign_approval(
            self.target_path, request.finding_id, request.reason.strip()
        )
        overview = self.bundle_overview()
        return {**overview, "state": "approval-complete", "event": event.model_dump(mode="json")}

    def _validate_through_facade(self, policy: ContractPolicy) -> PolicyValidationResult:
        with TemporaryDirectory(prefix="artifactdiff-review-policy-") as temporary:
            path = self.application.write_policy(policy, Path(temporary) / "policy.json")
            return self.application.validate_policy(self.target_path, path)

    def _require_mode(self, expected: str) -> None:
        if self.mode != expected:
            raise PolicyValidationError("review route is unavailable in this mode")

    def _verified_bundle(self) -> BundleVerification:
        verification = self.application.verify_bundle(self.target_path)
        if not verification.valid:
            raise ApprovalError("review bundle verification failed")
        return verification


def _policy_summary(policy: ContractPolicy, *, resolved_clause_id: str) -> dict[str, object]:
    default = ContractPolicy(baseline=policy.baseline)
    relaxations: list[dict[str, object]] = []
    comparisons = (
        ("protect", default.protect, policy.protect),
        (
            "metadata.non_business_change",
            default.metadata.non_business_change,
            policy.metadata.non_business_change,
        ),
        (
            "visual.explained_regions",
            default.visual.explained_regions,
            policy.visual.explained_regions,
        ),
        (
            "visual.pagination_reflow",
            default.visual.pagination_reflow,
            policy.visual.pagination_reflow,
        ),
        (
            "visual.protected_region_change",
            default.visual.protected_region_change,
            policy.visual.protected_region_change,
        ),
        ("visual.on_unavailable", default.visual.on_unavailable, policy.visual.on_unavailable),
        (
            "visual.layout_envelope_padding_points",
            default.visual.layout_envelope_padding_points,
            policy.visual.layout_envelope_padding_points,
        ),
        ("evidence.mode", default.evidence.mode, policy.evidence.mode),
    )
    for field, before, after in comparisons:
        if before != after:
            relaxations.append(
                {
                    "field": field,
                    "contract_safe": _summary_value(before),
                    "selected": _summary_value(after),
                }
            )
    rule = policy.expect[0]
    return {
        "intent": {"rule_id": rule.id, "operation": "exact_replace"},
        "baseline": policy.baseline.model_dump(mode="json"),
        "selector": rule.selector.model_dump(mode="json"),
        "selected_location": {
            "clause_id": resolved_clause_id,
            "clause_label": rule.selector.clause_label,
            "heading": rule.selector.heading,
            "ancestor_path": list(rule.selector.ancestor_path),
        },
        "operation": rule.operation.model_dump(mode="json"),
        "protect": sorted(item.value for item in policy.protect),
        "metadata": policy.metadata.model_dump(mode="json"),
        "visual": policy.visual.model_dump(mode="json"),
        "evidence": policy.evidence.model_dump(mode="json"),
        "required_plugins": policy.model_dump(mode="json")["required_plugins"],
        "canonical_sha256": policy_digest(policy),
        "canonical_size": len(canonical_policy_bytes(policy)),
        "assurance": "local",
        "relaxations": relaxations,
    }


def _summary_value(value: object) -> object:
    if isinstance(value, frozenset):
        return sorted(str(getattr(item, "value", item)) for item in value)
    return getattr(value, "value", value)


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


def _crop_payloads(bundle: Path, finding: Finding) -> list[dict[str, str]]:
    root = _normalized_bundle_root(bundle)
    if root is None:
        return []
    index = root / "core" / "evidence" / "index.json"
    try:
        index_raw = _read_controlled_file(root, index, maximum=1024 * 1024)
        if index_raw is None:
            return []
        evidence = EvidenceIndex.model_validate_json(index_raw)
    except (OSError, ValueError):
        return []
    linked = (
        item
        for item in evidence.items
        if finding.id in item.finding_ids and item.kind is EvidenceKind.CHANGED_REGION
    )
    crops: list[dict[str, str]] = []
    total_bytes = 0
    for item in linked:
        if (
            len(crops) == 20
            or item.size_bytes > 5 * 1024 * 1024
            or total_bytes + item.size_bytes > 5 * 1024 * 1024
        ):
            break
        path = root / "core" / "evidence" / Path(item.path)
        contents = _read_controlled_file(
            root,
            path,
            maximum=5 * 1024 * 1024,
            expected_size=item.size_bytes,
            expected_sha256=item.sha256,
        )
        if contents is None:
            return []
        suffix = path.suffix.casefold()
        media_type = (
            "image/png"
            if suffix == ".png"
            else "image/jpeg"
            if suffix in {".jpg", ".jpeg"}
            else None
        )
        if media_type is not None:
            crops.append(
                {
                    "path": item.path,
                    "data_url": f"data:{media_type};base64,{base64.b64encode(contents).decode('ascii')}",
                }
            )
            total_bytes += len(contents)
    return crops


def _event_history(
    application: ArtifactDiffApplication,
    bundle: Path,
    *,
    cursor: int,
    limit: int,
) -> tuple[dict[str, object], str]:
    if cursor < 0 or limit < 1 or limit > 100:
        raise ApprovalError("invalid event history page")
    root = _normalized_bundle_root(bundle)
    if root is None:
        raise ApprovalError("invalid review bundle path")
    manifest_raw = _read_controlled_file(root, root / "core" / "manifest.json", maximum=1024 * 1024)
    if manifest_raw is None:
        raise ApprovalError("invalid review bundle manifest")
    try:
        manifest = BundleManifest.model_validate_json(manifest_raw)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise ApprovalError("invalid review bundle manifest") from None
    if manifest_raw != canonical_bytes(manifest):
        raise ApprovalError("invalid review bundle manifest")
    expected = {item.path: item for item in manifest.payloads if item.path.startswith("events/")}
    verdict_payload = next(
        (item for item in manifest.payloads if item.path == "core/verdict.json"), None
    )
    if verdict_payload is None:
        raise ApprovalError("invalid review bundle verdict")
    verdict_raw = _read_controlled_file(
        root,
        root / "core" / "verdict.json",
        maximum=10 * 1024 * 1024,
        expected_size=verdict_payload.size_bytes,
        expected_sha256=verdict_payload.sha256,
    )
    if verdict_raw is None:
        raise ApprovalError("invalid review bundle verdict")
    try:
        verdict = RawVerdict.model_validate_json(verdict_raw)
    except (ValidationError, RecursionError, TypeError, ValueError):
        raise ApprovalError("invalid review bundle verdict") from None
    if verdict_raw != canonical_bytes(verdict):
        raise ApprovalError("invalid review bundle verdict")
    events: list[SessionOpenedEvent | ApprovalEvent] = []
    approvals: list[ApprovalEvent] = []
    total_bytes = 0
    try:
        paths: list[Path] = []
        for path in (root / "events").iterdir():
            if path.suffix.casefold() != ".json":
                continue
            paths.append(path)
            if len(paths) > 1001:
                raise ApprovalError("event history exceeds the bounded bundle model")
        paths.sort()
        for path in paths:
            relative = path.relative_to(root).as_posix()
            payload = expected.get(relative)
            if path.name == "000001-session-opened.json":
                if payload is None:
                    raise ApprovalError("invalid session event binding")
                model: type[SessionOpenedEvent | ApprovalEvent] = SessionOpenedEvent
            elif path.name.endswith("-approval.json"):
                model = ApprovalEvent
            else:
                raise ApprovalError("invalid event history file")
            raw = _read_controlled_file(
                root,
                path,
                maximum=256 * 1024,
                expected_size=payload.size_bytes if payload is not None else None,
                expected_sha256=payload.sha256 if payload is not None else None,
            )
            if raw is None or total_bytes + len(raw) > 12 * 1024 * 1024:
                raise ApprovalError("invalid event history file")
            value = model.model_validate_json(raw)
            if raw != canonical_bytes(value):
                raise ApprovalError("invalid event history file")
            total_bytes += len(raw)
            events.append(value)
            if isinstance(value, ApprovalEvent):
                approvals.append(value)
    except ApprovalError:
        raise
    except (OSError, ValidationError, RecursionError, TypeError, ValueError):
        raise ApprovalError("invalid event history file") from None
    effective = application.validate_event_snapshot(manifest, verdict, tuple(approvals))
    total = len(events)
    selected = events[cursor : cursor + limit]
    items: list[dict[str, object]] = []
    for value in selected:
        serialized = value.model_dump(mode="json")
        items.append(
            {
                key: serialized[key]
                for key in ("sequence", "event_type", "finding_id", "decision", "reason")
                if key in serialized
            }
        )
    next_cursor = cursor + len(selected) if cursor + len(selected) < total else None
    return (
        {
            "items": items,
            "total": total,
            "cursor": cursor,
            "next_cursor": next_cursor,
            "truncated": next_cursor is not None,
        },
        effective.event_chain_head,
    )


def _normalized_bundle_root(bundle: Path) -> Path | None:
    try:
        if bundle.is_symlink():
            return None
        root = bundle.resolve(strict=True)
        if not root.is_dir():
            return None
        return root
    except OSError:
        return None


def _read_controlled_file(
    root: Path,
    path: Path,
    *,
    maximum: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes | None:
    descriptor: int | None = None
    try:
        if path.is_symlink() or path.resolve(strict=True) != path:
            return None
        path.relative_to(root)
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            return None
        if expected_size is not None and before.st_size != expected_size:
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return None
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
    except (OSError, ValueError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        len(contents) > maximum
        or opened.st_size != len(contents)
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or (expected_size is not None and len(contents) != expected_size)
        or (expected_sha256 is not None and hashlib.sha256(contents).hexdigest() != expected_sha256)
    ):
        return None
    return contents


def public_view_error(error: Exception) -> tuple[int, str]:
    if isinstance(error, (ValidationError, ValueError, json.JSONDecodeError)):
        return 422, "invalid review request"
    if isinstance(error, ApprovalError):
        return 409, str(error)
    if isinstance(error, ArtifactDiffError):
        return 422, str(error)
    return 500, "review operation failed"
