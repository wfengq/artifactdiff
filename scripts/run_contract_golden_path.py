"""Run ArtifactDiff's signed, synthetic contract Golden Path.

This source-tree demo intentionally uses ephemeral in-memory Ed25519 keys. It writes
only public trust metadata and signed artifacts; no private key is persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from reportlab.pdfgen.canvas import Canvas

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
from artifactdiff.errors import SignatureError
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.trust import (
    SignatureEnvelope,
    TrustIdentity,
    TrustRole,
    TrustStore,
    sign_digest,
)
from artifactdiff.verification import FindingOutcome
from artifactdiff.verification.service import VerificationOptions

_PAYMENT_30 = (
    "Party A: Example Ltd.; on 2026-08-04, Party A shall pay RMB 10,000.00 "
    "within 30 days with a 5% late fee."
)
_PAYMENT_45 = _PAYMENT_30.replace("30 days", "45 days")
_PAYMENT_UNAUTHORIZED = _PAYMENT_45.replace("Example Ltd.", "Acme Corporation")


@dataclass(frozen=True, slots=True)
class MemorySigner:
    """Small demo-only signing provider that never writes its private key."""

    private_key: Ed25519PrivateKey
    identity: TrustIdentity

    def sign(self, *, purpose: str, digest: str, required_role: TrustRole) -> SignatureEnvelope:
        if required_role not in self.identity.roles:
            raise SignatureError("demo signer lacks the required role")
        return sign_digest(
            self.private_key,
            identity=self.identity,
            purpose=purpose,
            digest=digest,
        )


@dataclass(frozen=True, slots=True)
class GoldenCaseResult:
    name: str
    bundle: Path
    raw_outcome: FindingOutcome
    preapproval_outcome: FindingOutcome
    effective_outcome: FindingOutcome
    assurance: str
    bundle_valid: bool
    signature_valid_at_creation: bool | None
    currently_trusted: bool | None
    event_chain_valid: bool
    finding_ids: tuple[str, ...]
    approved_finding_ids: tuple[str, ...]
    nonapprovable_finding_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GoldenPathResult:
    root: Path
    summary_path: Path
    cases: dict[str, GoldenCaseResult]
    _application: ArtifactDiffApplication = field(repr=False)
    _approver: MemorySigner = field(repr=False)
    _unauthorized_bundle: Path = field(repr=False)
    _unauthorized_finding_id: str = field(repr=False)

    def attempt_unauthorized_approval(self) -> None:
        """Prove that the selected nonapprovable FAIL cannot be overridden."""
        self._application.approve(
            self._unauthorized_bundle,
            self._unauthorized_finding_id,
            "Synthetic reviewer attempted to approve a forbidden contract change.",
            signer=self._approver,
        )


def _identity(private_key: Ed25519PrivateKey, *, identity: str, role: TrustRole) -> TrustIdentity:
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TrustIdentity(
        id=identity,
        subject_type=(
            "human"
            if role in {TrustRole.POLICY_AUTHORIZER, TrustRole.FINDING_APPROVER}
            else "service"
        ),
        public_key_fingerprint=hashlib.sha256(public_der).hexdigest(),
        public_key_pem=public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii"),
        roles=frozenset({role}),
    )


def _signer(identity: str, role: TrustRole) -> MemorySigner:
    key = Ed25519PrivateKey.generate()
    return MemorySigner(key, _identity(key, identity=identity, role=role))


def _write_contract(
    path: Path,
    *,
    payment_line: str,
    extra_visual_mark: bool = False,
) -> Path:
    """Write one deterministic, redistributable synthetic contract PDF."""
    lines = (
        "MASTER SERVICES AGREEMENT AD-GOLDEN-001",
        "Article I Parties",
        "Party A and Party B enter this agreement on equal terms.",
        "Article II Payment Terms",
        payment_line,
        "Article III General Terms",
        "This agreement is governed by the applicable law.",
        "Signature: Authorized Representative",
        "Article IV Attachment",
        "Attachment A: Price Schedule",
    )
    canvas = Canvas(str(path), invariant=1, pageCompression=1)
    canvas.setAuthor("ArtifactDiff synthetic demo")
    canvas.setTitle("Synthetic Contract AD-GOLDEN-001")
    canvas.setFont("Helvetica", 10)
    y = 740
    for line in lines:
        canvas.drawString(54, y, line)
        y -= 30
    if extra_visual_mark:
        canvas.rect(500, 400, 18, 18, fill=1, stroke=0)
    canvas.save()
    return path


def _case_result(
    *,
    name: str,
    bundle: Path,
    application: ArtifactDiffApplication,
    preapproval_outcome: FindingOutcome,
) -> GoldenCaseResult:
    verification = application.verify_bundle(bundle)
    effective = application.effective_verdict(bundle)
    findings = application.list_findings(bundle)
    return GoldenCaseResult(
        name=name,
        bundle=bundle,
        raw_outcome=effective.raw_outcome,
        preapproval_outcome=preapproval_outcome,
        effective_outcome=effective.outcome,
        assurance=verification.assurance.value,
        bundle_valid=verification.valid,
        signature_valid_at_creation=verification.signature_valid_at_creation,
        currently_trusted=verification.currently_trusted,
        event_chain_valid=verification.event_chain_valid,
        finding_ids=tuple(item.id for item in findings),
        approved_finding_ids=tuple(effective.approved_finding_ids),
        nonapprovable_finding_ids=tuple(
            item.id
            for item in findings
            if item.outcome is FindingOutcome.FAIL and not item.approvable
        ),
    )


def _summary_payload(result: GoldenPathResult) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "privacy": "synthetic-data-only; private signing keys were not persisted",
        "cases": {
            name: {
                "bundle": str(case.bundle.resolve()),
                "raw_outcome": case.raw_outcome.value,
                "preapproval_outcome": case.preapproval_outcome.value,
                "effective_outcome": case.effective_outcome.value,
                "assurance": case.assurance,
                "bundle_valid": case.bundle_valid,
                "signature_valid_at_creation": case.signature_valid_at_creation,
                "currently_trusted": case.currently_trusted,
                "event_chain_valid": case.event_chain_valid,
                "finding_ids": list(case.finding_ids),
                "approved_finding_ids": list(case.approved_finding_ids),
                "nonapprovable_finding_ids": list(case.nonapprovable_finding_ids),
            }
            for name, case in sorted(result.cases.items())
        },
    }


def run_golden_path(root: Path, *, approve_review: bool = False) -> GoldenPathResult:
    """Execute PASS, REVIEW, and FAIL through signed policy/session/bundle boundaries."""
    root = root.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("golden path output directory must be empty")
    root.mkdir(parents=True, exist_ok=True)
    inputs = root / "inputs"
    sessions = root / "sessions"
    bundles = root / "bundles"
    for directory in (inputs, sessions, bundles):
        directory.mkdir()

    authorizer = _signer("demo-policy-authorizer", TrustRole.POLICY_AUTHORIZER)
    archive = _signer("demo-archive-signer", TrustRole.ARCHIVE_SIGNER)
    approver = _signer("demo-human-reviewer", TrustRole.FINDING_APPROVER)
    trust_store = TrustStore(identities=[authorizer.identity, archive.identity, approver.identity])
    (inputs / "trust-store.json").write_text(
        trust_store.model_dump_json(indent=2), encoding="utf-8"
    )

    baseline = _write_contract(inputs / "baseline.pdf", payment_line=_PAYMENT_30)
    authoring = ArtifactDiffApplication(trust_store=trust_store)
    policy = authoring.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="article ii",
            heading="Payment Terms",
            anchor="within 30 days",
        ),
        before="30 days",
        after="45 days",
        rule_id="payment-window",
    )
    policy_path = authoring.write_policy(policy, inputs / "policy.json")
    sealed_policy = authoring.seal_policy(
        baseline,
        policy_path,
        inputs / "sealed-policy.json",
        signer=authorizer,
    )

    session_application = ArtifactDiffApplication(
        trust_store=trust_store,
        path_policy=PathPolicy(input_roots=(inputs,), output_roots=(sessions,)),
    )
    application = ArtifactDiffApplication(
        trust_store=trust_store,
        manifest_signer=archive,
    )
    scenarios = {
        "authorized": (_PAYMENT_45, False),
        "review": (_PAYMENT_45, True),
        "unauthorized": (_PAYMENT_UNAUTHORIZED, False),
    }
    cases: dict[str, GoldenCaseResult] = {}
    unauthorized_bundle: Path | None = None
    unauthorized_finding_id: str | None = None

    for name, (payment_line, extra_mark) in scenarios.items():
        session = session_application.open_verified_session(
            baseline,
            sealed_policy,
            sessions,
            session_signer=archive,
        )
        _write_contract(
            session.candidate_path,
            payment_line=payment_line,
            extra_visual_mark=extra_mark,
        )
        bundle = application.verify_change(
            baseline,
            session.candidate_path,
            sealed_policy,
            bundles / name,
            VerificationOptions(),
            session_path=session.root_path,
        )
        preapproval = application.effective_verdict(bundle).outcome
        findings = application.list_findings(bundle)
        if name == "review" and approve_review:
            for finding in findings:
                if finding.outcome is FindingOutcome.REVIEW and finding.approvable:
                    application.approve(
                        bundle,
                        finding.id,
                        "Synthetic human reviewed the exact visual exception for this demo.",
                        signer=approver,
                    )
        if name == "unauthorized":
            nonapprovable = [
                item
                for item in findings
                if item.outcome is FindingOutcome.FAIL and not item.approvable
            ]
            if not nonapprovable:
                raise AssertionError("unauthorized scenario produced no nonapprovable FAIL")
            unauthorized_bundle = bundle
            unauthorized_finding_id = nonapprovable[0].id
        cases[name] = _case_result(
            name=name,
            bundle=bundle,
            application=application,
            preapproval_outcome=preapproval,
        )

    if unauthorized_bundle is None or unauthorized_finding_id is None:
        raise AssertionError("unauthorized scenario was not executed")
    summary_path = root / "summary.json"
    result = GoldenPathResult(
        root=root,
        summary_path=summary_path,
        cases=cases,
        _application=application,
        _approver=approver,
        _unauthorized_bundle=unauthorized_bundle,
        _unauthorized_finding_id=unauthorized_finding_id,
    )
    summary_path.write_text(
        json.dumps(_summary_payload(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build/contract-golden-path"),
        help="empty destination for synthetic inputs, sessions, bundles, and summary",
    )
    parser.add_argument(
        "--approve-review",
        action="store_true",
        help="simulate an explicit human approval of approvable REVIEW findings",
    )
    arguments = parser.parse_args()
    result = run_golden_path(arguments.output, approve_review=arguments.approve_review)
    print(result.summary_path.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
