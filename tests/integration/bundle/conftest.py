from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from artifactdiff.bundle import BundleAssurance
from artifactdiff.contract import (
    ClauseLabel,
    ClauseSelector,
    ContractClause,
    ContractDocument,
    LanguageKind,
    LanguageProfile,
)
from artifactdiff.errors import SignatureError
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.models import ComparisonResult, SourceDescriptor
from artifactdiff.normalize import fingerprint, normalize_text
from artifactdiff.policy import FrozenPolicy, draft_exact_replace_policy, freeze_policy
from artifactdiff.session import authorize_policy, open_verified_edit_session
from artifactdiff.trust import (
    PolicyAuthorization,
    SignatureEnvelope,
    TrustIdentity,
    TrustRole,
    TrustStore,
    sign_digest,
)
from artifactdiff.verification import ContractChangeSet, FindingOutcome, RawVerdict
from artifactdiff.verification.reporting import VerificationRun


@dataclass(frozen=True, slots=True)
class MemorySigner:
    private_key: Ed25519PrivateKey
    identity: TrustIdentity

    def sign(
        self,
        *,
        purpose: str,
        digest: str,
        required_role: TrustRole,
    ) -> SignatureEnvelope:
        if required_role not in self.identity.roles:
            raise SignatureError("test signer lacks required role")
        return sign_digest(
            self.private_key,
            identity=self.identity,
            purpose=purpose,
            digest=digest,
        )


@dataclass(frozen=True, slots=True)
class BundleFixture:
    run: VerificationRun
    frozen: FrozenPolicy
    destination: Path
    authorization: PolicyAuthorization
    session_event: object
    archive_signer: MemorySigner
    trust_store: TrustStore

    def local_args(self) -> dict[str, object]:
        return {
            "run": self.run,
            "frozen": self.frozen,
            "destination": self.destination,
            "assurance": BundleAssurance.LOCAL,
        }

    def verified_args(self, *, manifest_signer: object | None) -> dict[str, object]:
        return {
            "run": self.run,
            "frozen": self.frozen,
            "destination": self.destination,
            "assurance": BundleAssurance.VERIFIED,
            "policy_authorization": self.authorization,
            "session_event": self.session_event,
            "manifest_signer": manifest_signer,
        }


def _identity(
    private_key: Ed25519PrivateKey,
    *,
    identity: str,
    role: TrustRole,
) -> TrustIdentity:
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return TrustIdentity(
        id=identity,
        subject_type="human" if role is TrustRole.POLICY_AUTHORIZER else "service",
        public_key_fingerprint=hashlib.sha256(public_der).hexdigest(),
        public_key_pem=public_pem,
        roles=frozenset({role}),
    )


@pytest.fixture
def bundle_fixture(tmp_path: Path) -> BundleFixture:
    input_root = tmp_path / "input"
    session_root = tmp_path / "sessions-output"
    destination = tmp_path / "bundles"
    input_root.mkdir()
    session_root.mkdir()
    destination.mkdir()
    baseline = input_root / "baseline.docx"
    baseline.write_bytes(b"ArtifactDiff immutable review bundle baseline\n")

    clause_text = "Section 4 Payment Terms\nPayment is due within 30 days."
    clause = ContractClause(
        id="clause-payment",
        label=ClauseLabel(
            printed="Section 4",
            normalized=normalize_text("Section 4"),
            scheme="section",
        ),
        heading="Payment Terms",
        ancestor_path=("Agreement",),
        text=clause_text,
        normalized_text=normalize_text(clause_text),
        fingerprint=fingerprint(clause_text),
    )
    contract = ContractDocument(
        source=SourceDescriptor.from_path(baseline),
        language=LanguageProfile(kind=LanguageKind.ENGLISH),
        clauses=[clause],
    )
    policy = draft_exact_replace_policy(
        contract,
        ClauseSelector(
            clause_label=clause.label.normalized,
            heading=clause.heading,
            ancestor_path=clause.ancestor_path,
            anchor="Payment is due within 30 days.",
        ),
        before="30 days",
        after="45 days",
        rule_id="payment-window",
    )
    frozen = freeze_policy(contract, policy)

    candidate_sha256 = "b" * 64
    facts = ContractChangeSet(
        baseline_sha256=contract.source.sha256,
        candidate_sha256=candidate_sha256,
    )
    verdict = RawVerdict(
        outcome=FindingOutcome.PASS,
        policy_sha256=frozen.canonical_sha256,
        baseline_sha256=contract.source.sha256,
        candidate_sha256=candidate_sha256,
        findings=[],
    )
    comparison = ComparisonResult(
        status="changed",
        before=SourceDescriptor(
            path="C:/private/customer/baseline.docx",
            sha256=contract.source.sha256,
            format="docx",
            size_bytes=baseline.stat().st_size,
        ),
        after=SourceDescriptor(
            path="C:/private/customer/candidate.docx",
            sha256=candidate_sha256,
            format="docx",
            size_bytes=baseline.stat().st_size,
        ),
    )
    verification_json = tmp_path / "verification.json"
    verification_json.write_text("{}", encoding="utf-8")
    run = VerificationRun(
        result=verdict,
        facts=facts,
        comparison=comparison,
        json_path=verification_json,
        visual_assets={},
    )

    authorizer_key = Ed25519PrivateKey.generate()
    archive_key = Ed25519PrivateKey.generate()
    authorizer = _identity(
        authorizer_key,
        identity="bundle-policy-authorizer",
        role=TrustRole.POLICY_AUTHORIZER,
    )
    archive_identity = _identity(
        archive_key,
        identity="bundle-archive-signer",
        role=TrustRole.ARCHIVE_SIGNER,
    )
    authorizer_signer = MemorySigner(authorizer_key, authorizer)
    archive_signer = MemorySigner(archive_key, archive_identity)
    authorization = authorize_policy(frozen, signer=authorizer_signer)
    trust_store = TrustStore(identities=[authorizer, archive_identity])
    session = open_verified_edit_session(
        baseline,
        frozen,
        authorization,
        root=session_root,
        trust_store=trust_store,
        session_signer=archive_signer,
        path_policy=PathPolicy(
            input_roots=(input_root,),
            output_roots=(session_root,),
        ),
    )
    return BundleFixture(
        run=run,
        frozen=frozen,
        destination=destination,
        authorization=authorization,
        session_event=session.events[0],
        archive_signer=archive_signer,
        trust_store=trust_store,
    )
