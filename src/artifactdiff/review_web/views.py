"""Authenticated, bounded JSON views for one local contract review task."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.bundle import BundleVerification
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
from artifactdiff.review_web.signing_provider import ReviewSigningProvider
from artifactdiff.session import SealedPolicyArtifact
from artifactdiff.verification import Finding, FindingOutcome


class _ViewModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PolicyDraftRequest(_ViewModel):
    rule_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    selector: ClauseSelector
    before: str = Field(min_length=1, max_length=10_000)
    after: str = Field(min_length=1, max_length=10_000)
    protect: list[str] | None = None
    metadata: MetadataPolicy | None = None
    visual: VisualPolicy | None = None
    evidence: EvidencePolicy | None = None
    required_plugins: dict[str, PolicyPluginRequirement] | None = None


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
                    "excerpt": str(value.get("text", ""))[:512],
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
            request.selector,
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
        self._validate_through_facade(policy)
        self._draft = policy
        if self.output_path is not None:
            self.application.write_policy(policy, self.output_path)
        return {
            "state": "policy-ready",
            "policy": policy.model_dump(mode="json"),
            "summary": _policy_summary(policy),
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
        return {
            "state": "policy-ready",
            "assurance": request.assurance,
            "artifact": artifact.model_dump(mode="json"),
        }

    def bundle_overview(self) -> dict[str, object]:
        self._require_mode("bundle")
        verification = self._verified_bundle()
        effective = self.application.effective_verdict(self.target_path)
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
            "event_history": _event_history(self.target_path),
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
        return {
            "state": "approval-complete",
            "event": event.model_dump(mode="json"),
            "effective_verdict": self.application.effective_verdict(self.target_path).model_dump(
                mode="json"
            ),
        }

    def _validate_through_facade(self, policy: ContractPolicy) -> None:
        with TemporaryDirectory(prefix="artifactdiff-review-policy-") as temporary:
            path = self.application.write_policy(policy, Path(temporary) / "policy.json")
            self.application.validate_policy(self.target_path, path)

    def _require_mode(self, expected: str) -> None:
        if self.mode != expected:
            raise PolicyValidationError("review route is unavailable in this mode")

    def _verified_bundle(self) -> BundleVerification:
        verification = self.application.verify_bundle(self.target_path)
        if not verification.valid:
            raise ApprovalError("review bundle verification failed")
        return verification


def _policy_summary(policy: ContractPolicy) -> dict[str, object]:
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
    index = bundle / "core" / "evidence" / "index.json"
    try:
        evidence = EvidenceIndex.model_validate_json(index.read_bytes())
    except (OSError, ValueError):
        return []
    linked = (
        item
        for item in evidence.items
        if finding.id in item.finding_ids and item.kind is EvidenceKind.CHANGED_REGION
    )
    crops: list[dict[str, str]] = []
    for item in linked:
        if len(crops) == 20 or item.size_bytes > 5 * 1024 * 1024:
            break
        path = bundle / "core" / "evidence" / Path(item.path)
        try:
            contents = path.read_bytes()
        except OSError:
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
    return crops


def _event_history(bundle: Path) -> list[dict[str, object]]:
    history: list[dict[str, object]] = []
    try:
        paths = sorted((bundle / "events").glob("*.json"))[:100]
        for path in paths:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                continue
            history.append(
                {
                    key: value[key]
                    for key in ("sequence", "event_type", "finding_id", "decision", "reason")
                    if key in value
                }
            )
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return []
    return history


def public_view_error(error: Exception) -> tuple[int, str]:
    if isinstance(error, (ValidationError, ValueError, json.JSONDecodeError)):
        return 422, "invalid review request"
    if isinstance(error, ApprovalError):
        return 409, str(error)
    if isinstance(error, ArtifactDiffError):
        return 422, str(error)
    return 500, "review operation failed"
