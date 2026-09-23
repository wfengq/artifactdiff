"""Stdio MCP adapter exposing bounded ArtifactDiff operations."""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import wraps
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from artifactdiff.application import (
    ArtifactDiffApplication,
    GeneratedReviewBundleSnapshot,
    SealedLocalPolicyResult,
)
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import (
    ApprovalError,
    ArtifactDiffError,
    BundleError,
    InputValidationError,
    PathSafetyError,
    SignatureError,
)
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.limits import validate_source
from artifactdiff.mcp_paths import McpRoots, trust_store_path_from_environment
from artifactdiff.models import BlockRef, SourceDescriptor
from artifactdiff.policy import policy_digest
from artifactdiff.service import CompareOptions, ComparisonRun, compare_documents, inspect_document
from artifactdiff.trust import TrustStore
from artifactdiff.verification import Finding
from artifactdiff.verification.service import VerificationOptions

_MAX_ITEMS = 20
_MAX_PAGE_SIZE = 100
_MAX_EXCERPT = 2_000
_MAX_SELECTOR_LABEL = 256
_MAX_SELECTOR_HEADING = 512
_MAX_SELECTOR_ANCHOR = 2_000
_MAX_ANCESTOR_ITEMS = 16
_MAX_ANCESTOR_ITEM = 256
_MAX_POLICY_REPLACEMENT = 4_000
_MAX_RULE_ID = 64
_MAX_POLICY_BYTES = 16_384
_MAX_TRUST_STORE_BYTES = 1024 * 1024


def _error_response(error: ArtifactDiffError) -> dict[str, object]:
    return {"ok": False, "error_type": type(error).__name__, "error": str(error)}


def _absolute_output_dir(
    output_dir: str | None, before: Path, after: Path, *, output_root: Path
) -> Path:
    if output_dir is not None:
        destination = Path(output_dir)
        if not destination.is_absolute():
            raise PathSafetyError(f"output directory must be absolute: {output_dir}")
        return destination
    before_hash = SourceDescriptor.from_path(before).sha256[:12]
    after_hash = SourceDescriptor.from_path(after).sha256[:12]
    return output_root / "artifactdiff-reports" / f"{before_hash}-{after_hash}"


def _bounded_comparison_response(run: ComparisonRun) -> dict[str, object]:
    changes = run.result.changes[:_MAX_ITEMS]
    return {
        "ok": True,
        "schema_version": run.result.schema_version,
        "status": run.result.status,
        "summary": run.result.summary.model_dump(mode="json"),
        "warnings": list(run.result.warnings),
        "changes": [
            {
                "id": change.id,
                "kind": change.kind,
                "content_type": change.content_type,
                "severity": change.severity,
                "similarity": change.similarity,
                "before": _bounded_block_reference(change.before),
                "after": _bounded_block_reference(change.after),
            }
            for change in changes
        ],
        "truncated_changes": len(run.result.changes) > len(changes),
        "reports": {
            "json": str(run.json_path.resolve()),
            "html": str(run.html_path.resolve()) if run.html_path is not None else None,
        },
    }


def _bounded_block_reference(reference: BlockRef | None) -> dict[str, object] | None:
    if reference is None:
        return None
    return {
        "block_id": reference.block_id,
        "ordinal": reference.ordinal,
        "page_index": reference.page_index,
    }


def _bounded_document_inspection(inspection: dict[str, object]) -> dict[str, object]:
    blocks = inspection.get("blocks")
    bounded_blocks = []
    if isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, dict):
                bounded_blocks.append(
                    {
                        "id": block.get("id"),
                        "ordinal": block.get("ordinal"),
                        "page_index": block.get("page_index"),
                        "content_type": block.get("content_type"),
                        "bbox": block.get("bbox"),
                    }
                )
    warnings = inspection.get("warnings")
    return {
        "ok": True,
        "path": inspection.get("path"),
        "format": inspection.get("format"),
        "sha256": inspection.get("sha256"),
        "size_bytes": inspection.get("size_bytes"),
        "page_count": inspection.get("page_count"),
        "blocks": bounded_blocks,
        "warnings": list(warnings) if isinstance(warnings, list) else [],
        "truncated": bool(inspection.get("truncated", False)),
    }


def _bounded_clause(value: dict[str, object]) -> dict[str, object]:
    label = value.get("label")
    return {
        "id": value.get("id"),
        "label": _bounded_text(label.get("normalized"), _MAX_SELECTOR_LABEL)
        if isinstance(label, dict)
        else None,
        "heading": _bounded_text(value.get("heading"), _MAX_SELECTOR_HEADING),
        "ancestor_path": _bounded_ancestor_path(value.get("ancestor_path")),
        "fingerprint": value.get("fingerprint"),
    }


def _bounded_text(value: object, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _bounded_ancestor_path(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [
        item[:_MAX_ANCESTOR_ITEM] for item in value[:_MAX_ANCESTOR_ITEMS] if isinstance(item, str)
    ]


def _selector_candidates(inspection: dict[str, object]) -> list[dict[str, object]]:
    clauses = inspection.get("clauses", [])
    if not isinstance(clauses, list):
        return []
    return [_bounded_clause(clause) for clause in clauses[:_MAX_ITEMS] if isinstance(clause, dict)]


def _bounded_independent_headings(inspection: dict[str, object]) -> tuple[list[str], bool]:
    headings = inspection.get("independent_headings", [])
    if not isinstance(headings, list):
        return [], bool(inspection.get("truncated_headings", False))
    values = [heading for heading in headings if isinstance(heading, str)]
    selected = values[:_MAX_ITEMS]
    truncated = (
        bool(inspection.get("truncated_headings", False))
        or len(values) > len(selected)
        or any(len(heading) > _MAX_SELECTOR_HEADING for heading in selected)
    )
    return [heading[:_MAX_SELECTOR_HEADING] for heading in selected], truncated


def _finding_summary(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "outcome": finding.outcome.value,
        "selector_status": (
            finding.selector_status.value if finding.selector_status is not None else None
        ),
        "approvable": finding.approvable,
    }


def _finding_detail(finding: Finding) -> dict[str, object]:
    evidence = finding.evidence
    return {
        **_finding_summary(finding),
        "location": finding.location,
        "remediation": finding.remediation,
        "before_excerpt": (evidence.before_excerpt or "")[:_MAX_EXCERPT],
        "after_excerpt": (evidence.after_excerpt or "")[:_MAX_EXCERPT],
        "crop_paths": [],
    }


def _with_error_boundary(
    function: Callable[..., Awaitable[dict[str, object]]],
) -> Callable[..., Awaitable[dict[str, object]]]:
    """Translate only deliberately public domain errors at the MCP boundary."""

    @wraps(function)
    async def wrapped(*args: object, **kwargs: object) -> dict[str, object]:
        try:
            return await function(*args, **kwargs)
        except ArtifactDiffError as error:
            return _error_response(error)

    return wrapped


def _require_text_budget(value: str, label: str, maximum: int) -> None:
    if len(value) > maximum:
        raise InputValidationError(f"{label} exceeds the MCP input limit")


def _validate_draft_request(
    *,
    clause_label: str,
    heading: str,
    anchor: str,
    before: str,
    after: str,
    rule_id: str,
    ancestor_path: list[str] | None,
) -> None:
    _require_text_budget(clause_label, "clause_label", _MAX_SELECTOR_LABEL)
    _require_text_budget(heading, "heading", _MAX_SELECTOR_HEADING)
    _require_text_budget(anchor, "anchor", _MAX_SELECTOR_ANCHOR)
    _require_text_budget(before, "before", _MAX_POLICY_REPLACEMENT)
    _require_text_budget(after, "after", _MAX_POLICY_REPLACEMENT)
    _require_text_budget(rule_id, "rule_id", _MAX_RULE_ID)
    if ancestor_path is not None:
        if len(ancestor_path) > _MAX_ANCESTOR_ITEMS:
            raise InputValidationError("ancestor_path exceeds the MCP input limit")
        for item in ancestor_path:
            _require_text_budget(item, "ancestor_path item", _MAX_ANCESTOR_ITEM)
    payload = {
        "rule_id": rule_id,
        "selector": {
            "clause_label": clause_label,
            "heading": heading,
            "anchor": anchor,
            "ancestor_path": ancestor_path or [],
        },
        "before": before,
        "after": after,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > _MAX_POLICY_BYTES:
        raise InputValidationError("draft request exceeds the MCP aggregate limit")


@dataclass(frozen=True, slots=True)
class _GeneratedArtifact:
    kind: str
    path: Path
    value: SealedLocalPolicyResult | GeneratedReviewBundleSnapshot


class _GeneratedArtifactRegistry:
    """Per-server capabilities for artifacts created by this MCP instance only."""

    def __init__(self) -> None:
        self._records: dict[Path, _GeneratedArtifact] = {}

    def register_sealed_policy(self, result: SealedLocalPolicyResult) -> Path:
        path = _lexical_absolute(result.path)
        self._records[path] = _GeneratedArtifact("sealed_policy", path, result)
        return path

    def register_bundle(self, path: Path, snapshot: GeneratedReviewBundleSnapshot) -> Path:
        resolved = _lexical_absolute(path)
        self._records[resolved] = _GeneratedArtifact("review_bundle", resolved, snapshot)
        return resolved

    def sealed_policy(self, path: Path) -> SealedLocalPolicyResult | None:
        value = self._lookup(path, "sealed_policy")
        return value if isinstance(value, SealedLocalPolicyResult) else None

    def review_bundle(self, path: Path) -> GeneratedReviewBundleSnapshot | None:
        value = self._lookup(path, "review_bundle")
        return value if isinstance(value, GeneratedReviewBundleSnapshot) else None

    def _lookup(
        self, path: Path, kind: str
    ) -> SealedLocalPolicyResult | GeneratedReviewBundleSnapshot | None:
        if not path.is_absolute():
            return None
        record = self._records.get(_lexical_absolute(path))
        if record is None:
            return None
        if record.kind != kind:
            raise PathSafetyError("generated artifact kind does not match this MCP operation")
        return record.value


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _environment_trust_store(policy: PathPolicy) -> TrustStore:
    try:
        path = trust_store_path_from_environment()
        if path is None:
            return TrustStore(identities=[])
        resolved = policy.resolve_input(path)
        if resolved.stat().st_size > _MAX_TRUST_STORE_BYTES:
            raise SignatureError("invalid MCP trust store configuration")
        with resolved.open("rb") as stream:
            raw = stream.read(_MAX_TRUST_STORE_BYTES + 1)
        if len(raw) > _MAX_TRUST_STORE_BYTES:
            raise SignatureError("invalid MCP trust store configuration")
        return TrustStore.model_validate_json(raw)
    except (ArtifactDiffError, OSError, OverflowError, RecursionError, TypeError, ValueError):
        raise SignatureError("invalid MCP trust store configuration") from None


def create_mcp(roots: McpRoots | None = None, *, trust_store: TrustStore | None = None) -> FastMCP:
    """Create one MCP server whose file access is constrained to *roots*."""
    configured_roots = roots if roots is not None else McpRoots.from_environment()
    policy = configured_roots.path_policy() if configured_roots.enabled else None
    trust_configuration_error: SignatureError | None = None
    configured_trust_store = TrustStore(identities=[])
    if policy is not None:
        try:
            configured_trust_store = (
                TrustStore.model_validate(trust_store)
                if trust_store is not None
                else _environment_trust_store(policy)
            )
        except (SignatureError, OverflowError, RecursionError, TypeError, ValueError):
            trust_configuration_error = SignatureError("invalid MCP trust store configuration")
    application = (
        ArtifactDiffApplication(trust_store=configured_trust_store, path_policy=policy)
        if policy is not None
        else None
    )
    generated = _GeneratedArtifactRegistry() if policy is not None else None
    server = FastMCP("ArtifactDiff")

    def require_application() -> ArtifactDiffApplication:
        if application is None:
            raise PathSafetyError(
                "MCP file tools are disabled until input and output roots are configured"
            )
        return application

    def require_generated() -> _GeneratedArtifactRegistry:
        if generated is None:
            raise PathSafetyError(
                "MCP file tools are disabled until input and output roots are configured"
            )
        return generated

    @server.tool(name="compare_documents")
    @_with_error_boundary
    async def compare_documents_tool(
        before_path: str,
        after_path: str,
        output_dir: str | None = None,
        visual: bool = True,
        force: bool = False,
    ) -> dict[str, object]:
        app = require_application()
        before = app.path_policy.resolve_input(Path(before_path))  # type: ignore[union-attr]
        after = app.path_policy.resolve_input(Path(after_path))  # type: ignore[union-attr]
        destination = _absolute_output_dir(
            output_dir,
            before,
            after,
            output_root=app.path_policy.output_roots[0],  # type: ignore[union-attr]
        )
        destination = app.path_policy.resolve_output(destination)  # type: ignore[union-attr]
        run = compare_documents(
            validate_source(before, force=force, require_absolute=True),
            validate_source(after, force=force, require_absolute=True),
            destination,
            options=CompareOptions(visual=visual, force=force),
        )
        return _bounded_comparison_response(run)

    @server.tool(name="inspect_document")
    @_with_error_boundary
    async def inspect_document_tool(path: str, force: bool = False) -> dict[str, object]:
        app = require_application()
        source = app.path_policy.resolve_input(Path(path))  # type: ignore[union-attr]
        inspection = inspect_document(source, force=force, require_absolute=True, max_blocks=100)
        return _bounded_document_inspection(inspection)

    @server.tool(name="inspect_contract")
    @_with_error_boundary
    async def inspect_contract_tool(path: str) -> dict[str, object]:
        inspection = require_application().inspect_contract(Path(path), max_clauses=_MAX_ITEMS)
        candidates = _selector_candidates(inspection)
        headings, truncated_headings = _bounded_independent_headings(inspection)
        source = inspection.get("source")
        warnings = inspection.get("warnings")
        return {
            "ok": True,
            "schema_version": inspection.get("schema_version"),
            "source_sha256": source.get("sha256") if isinstance(source, dict) else None,
            "clauses": candidates,
            "independent_headings": headings,
            "truncated_clauses": bool(inspection.get("truncated_clauses", False)),
            "truncated_headings": truncated_headings,
            "warnings": list(warnings) if isinstance(warnings, list) else [],
        }

    @server.tool(name="draft_contract_policy")
    @_with_error_boundary
    async def draft_contract_policy_tool(
        baseline_path: str,
        clause_label: str,
        heading: str,
        anchor: str,
        before: str,
        after: str,
        rule_id: str,
        ancestor_path: list[str] | None = None,
    ) -> dict[str, object]:
        _validate_draft_request(
            clause_label=clause_label,
            heading=heading,
            anchor=anchor,
            before=before,
            after=after,
            rule_id=rule_id,
            ancestor_path=ancestor_path,
        )
        app = require_application()
        selector = ClauseSelector(
            clause_label=clause_label,
            heading=heading,
            anchor=anchor,
            ancestor_path=tuple(ancestor_path or ()),
        )
        policy_value = app.draft_policy(
            Path(baseline_path), selector, before=before, after=after, rule_id=rule_id
        )
        inspection = app.inspect_contract(Path(baseline_path), max_clauses=_MAX_ITEMS)
        payload = policy_value.model_dump(mode="json")
        if (
            len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            > _MAX_POLICY_BYTES
        ):
            raise InputValidationError("canonical policy exceeds the MCP response limit")
        return {
            "ok": True,
            "policy": payload,
            "policy_sha256": policy_digest(policy_value),
            "selector_candidates": _selector_candidates(inspection),
            "truncated_selector_candidates": bool(inspection.get("truncated_clauses", False)),
        }

    @server.tool(name="validate_contract_policy")
    @_with_error_boundary
    async def validate_contract_policy_tool(
        baseline_path: str, policy_path: str
    ) -> dict[str, object]:
        validated = require_application().validate_policy(Path(baseline_path), Path(policy_path))
        return {
            "ok": True,
            "policy_sha256": validated.policy_sha256,
            "resolved_clause_id": validated.resolved_clause_id,
        }

    @server.tool(name="seal_local_policy")
    @_with_error_boundary
    async def seal_local_policy_tool(
        baseline_path: str, policy_path: str, output_path: str
    ) -> dict[str, object]:
        sealed = require_application().seal_local_policy_artifact(
            Path(baseline_path), Path(policy_path), Path(output_path)
        )
        registered = require_generated().register_sealed_policy(sealed)
        return {"ok": True, "assurance": "local", "sealed_policy_path": str(registered)}

    @server.tool(name="verify_contract_change")
    @_with_error_boundary
    async def verify_contract_change_tool(
        baseline_path: str,
        candidate_path: str,
        sealed_policy_path: str,
        output_path: str,
        visual: bool = True,
    ) -> dict[str, object]:
        app = require_application()
        sealed = require_generated().sealed_policy(Path(sealed_policy_path))
        bundle = (
            app.verify_local_change_from_artifact(
                Path(baseline_path),
                Path(candidate_path),
                sealed.artifact,
                Path(output_path),
                VerificationOptions(visual=visual),
            )
            if sealed is not None
            else app.verify_local_change(
                Path(baseline_path),
                Path(candidate_path),
                Path(sealed_policy_path),
                Path(output_path),
                VerificationOptions(visual=visual),
            )
        )
        snapshot = app.snapshot_generated_local_bundle(bundle)
        registered_bundle = require_generated().register_bundle(bundle, snapshot)
        verification = snapshot.verification
        effective = snapshot.effective_verdict
        findings = snapshot.findings
        summaries = [_finding_summary(finding) for finding in findings[:_MAX_ITEMS]]
        return {
            "ok": True,
            "bundle_path": str(registered_bundle),
            "assurance": "local",
            "raw_verdict": effective.raw_outcome.value,
            "effective_verdict": effective.outcome.value,
            "findings": summaries,
            "truncated_findings": len(findings) > len(summaries),
            "bundle_valid": verification.valid,
        }

    @server.tool(name="list_review_findings")
    @_with_error_boundary
    async def list_review_findings_tool(
        bundle_path: str, cursor: int = 0, limit: int = _MAX_ITEMS
    ) -> dict[str, object]:
        if cursor < 0:
            raise PathSafetyError("finding cursor must be zero or greater")
        if not 1 <= limit <= _MAX_PAGE_SIZE:
            raise PathSafetyError("finding limit must be between 1 and 100")
        snapshot = require_generated().review_bundle(Path(bundle_path))
        findings = (
            list(snapshot.findings)
            if snapshot is not None
            else require_application().list_findings(Path(bundle_path))
        )
        selected = findings[cursor : cursor + limit]
        return {
            "ok": True,
            "findings": [_finding_summary(finding) for finding in selected],
            "cursor": cursor,
            "next_cursor": cursor + len(selected)
            if cursor + len(selected) < len(findings)
            else None,
            "truncated": cursor + len(selected) < len(findings),
        }

    @server.tool(name="get_review_finding")
    @_with_error_boundary
    async def get_review_finding_tool(bundle_path: str, finding_id: str) -> dict[str, object]:
        snapshot = require_generated().review_bundle(Path(bundle_path))
        if snapshot is None:
            finding = require_application().get_finding(Path(bundle_path), finding_id)
        else:
            matches = [finding for finding in snapshot.findings if finding.id == finding_id]
            if len(matches) != 1:
                raise ApprovalError("finding does not exist")
            finding = matches[0]
        return {"ok": True, "finding": _finding_detail(finding)}

    @server.tool(name="verify_review_bundle")
    @_with_error_boundary
    async def verify_review_bundle_tool(bundle_path: str) -> dict[str, object]:
        if trust_configuration_error is not None:
            raise trust_configuration_error
        app = require_application()
        snapshot = require_generated().review_bundle(Path(bundle_path))
        verification = (
            snapshot.verification if snapshot is not None else app.verify_bundle(Path(bundle_path))
        )
        if not verification.valid:
            raise BundleError("review bundle verification failed")
        effective = (
            snapshot.effective_verdict
            if snapshot is not None
            else app.effective_verdict(Path(bundle_path), require_current_trust=False)
        )
        return {
            "ok": True,
            "valid": verification.valid,
            "assurance": verification.assurance.value,
            "signature_valid_at_creation": verification.signature_valid_at_creation,
            "currently_trusted": verification.currently_trusted,
            "effective_outcome": effective.outcome.value,
        }

    return server


mcp = create_mcp()


def main() -> None:
    """Run the ArtifactDiff MCP server over standard input/output."""
    mcp.run(transport="stdio")
