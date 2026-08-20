"""The single public application boundary used by ArtifactDiff adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from artifactdiff.bundle import (
    BundleAssurance,
    BundleManifest,
    BundleVerification,
    verify_review_bundle,
    write_review_bundle,
)
from artifactdiff.contract import (
    ClauseSelector,
    ContractDocument,
    SelectorResolutionStatus,
    inspect_contract,
    load_contract,
    resolve_baseline,
)
from artifactdiff.errors import BundleError, PolicyValidationError, SessionError
from artifactdiff.evidence import pack_bundle
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.normalize import sha256_file
from artifactdiff.policy import (
    ContractPolicy,
    draft_exact_replace_policy,
    freeze_policy,
    load_policy,
    policy_digest,
    validate_policy,
    write_policy,
)
from artifactdiff.policy.models import EvidenceMode
from artifactdiff.review import (
    ApprovalEvent,
    EffectiveVerdict,
    approve_finding,
    list_findings,
    load_effective_verdict,
    validate_approval_event_snapshot,
)
from artifactdiff.session import (
    EditSession,
    SealedPolicyArtifact,
    claim_verified_candidate,
    load_edit_session,
    load_sealed_policy,
    open_verified_edit_session,
    write_sealed_policy,
)
from artifactdiff.trust import SigningProvider, TrustStore
from artifactdiff.verification import Finding, RawVerdict
from artifactdiff.verification.service import VerificationOptions, verify_contract_change


@dataclass(frozen=True, slots=True)
class PolicyValidationResult:
    """One validated policy and the bounded selector result shared by adapters."""

    policy: ContractPolicy
    policy_sha256: str
    resolved_clause_id: str


@dataclass(frozen=True, slots=True)
class SealedLocalPolicyResult:
    """One locally sealed policy and the immutable artifact written for an adapter."""

    path: Path
    artifact: SealedPolicyArtifact


@dataclass(frozen=True, slots=True)
class GeneratedReviewBundleSnapshot:
    """Immutable review data captured immediately after a generated local bundle is verified."""

    verification: BundleVerification
    effective_verdict: EffectiveVerdict
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class ArtifactDiffApplication:
    """Thin, path-safe composition of the domain services for every adapter."""

    trust_store: TrustStore
    path_policy: PathPolicy | None = None
    manifest_signer: SigningProvider | None = None

    def _input(self, path: Path) -> Path:
        return self.path_policy.resolve_input(path) if self.path_policy else path

    def _output(self, path: Path) -> Path:
        return self.path_policy.resolve_output(path) if self.path_policy else path

    def _directory_input(self, path: Path) -> Path:
        return self.path_policy.resolve_input_directory(path) if self.path_policy else path

    def _contract(self, path: Path) -> ContractDocument:
        source = self._input(path)
        with TemporaryDirectory(prefix="artifactdiff-application-") as temporary:
            _, contract = load_contract(source, render=False, force=False, workdir=Path(temporary))
        return contract

    def inspect_contract(self, path: Path, *, max_clauses: int = 100) -> dict[str, object]:
        return inspect_contract(self._input(path), max_clauses=max_clauses)

    def draft_policy(
        self,
        baseline: Path,
        selector: ClauseSelector,
        *,
        before: str,
        after: str,
        rule_id: str,
    ) -> ContractPolicy:
        return draft_exact_replace_policy(
            self._contract(baseline), selector, before=before, after=after, rule_id=rule_id
        )

    def write_policy(self, policy: ContractPolicy, output: Path, *, overwrite: bool = True) -> Path:
        try:
            return write_policy(policy, self._output(output), overwrite=overwrite)
        except OSError:
            raise PolicyValidationError("unable to write policy file") from None

    def validate_policy(self, baseline: Path, policy_path: Path) -> PolicyValidationResult:
        policy = load_policy(self._input(policy_path))
        contract = self._contract(baseline)
        validate_policy(contract, policy)
        resolution = resolve_baseline(contract, policy.expect[0].selector)
        if resolution.status is not SelectorResolutionStatus.UNIQUE or len(resolution.matches) != 1:
            raise PolicyValidationError("policy selector must resolve exactly once")
        return PolicyValidationResult(
            policy=policy,
            policy_sha256=policy_digest(policy),
            resolved_clause_id=resolution.matches[0].clause_id,
        )

    def seal_policy(
        self,
        baseline: Path,
        policy_path: Path,
        output: Path,
        *,
        signer: SigningProvider | None = None,
    ) -> Path:
        return self.seal_local_policy_artifact(baseline, policy_path, output, signer=signer).path

    def seal_local_policy_artifact(
        self,
        baseline: Path,
        policy_path: Path,
        output: Path,
        *,
        signer: SigningProvider | None = None,
    ) -> SealedLocalPolicyResult:
        """Freeze and write one policy while retaining the exact immutable artifact."""
        validated = self.validate_policy(baseline, policy_path)
        frozen = freeze_policy(self._contract(baseline), validated.policy)
        authorization = None
        if signer is not None:
            from artifactdiff.session import authorize_policy

            authorization = authorize_policy(frozen, signer=signer)
        artifact = SealedPolicyArtifact(frozen=frozen, authorization=authorization)
        path = write_sealed_policy(artifact, self._output(output))
        return SealedLocalPolicyResult(path=path, artifact=artifact)

    def open_verified_session(
        self,
        baseline: Path,
        sealed_policy: Path,
        output: Path,
        *,
        session_signer: SigningProvider,
    ) -> EditSession:
        if self.path_policy is None:
            from artifactdiff.errors import SessionError

            raise SessionError("verified sessions require configured path roots")
        artifact = load_sealed_policy(self._input(sealed_policy))
        if artifact.authorization is None:
            from artifactdiff.errors import SessionError

            raise SessionError("verified sessions require a signed policy artifact")
        return open_verified_edit_session(
            self._input(baseline),
            artifact.frozen,
            artifact.authorization,
            root=self._output(output),
            trust_store=self.trust_store,
            session_signer=session_signer,
            path_policy=self.path_policy,
        )

    def verify_change(
        self,
        baseline: Path,
        candidate: Path,
        sealed_policy: Path,
        output: Path,
        options: VerificationOptions,
        session_path: Path | None = None,
    ) -> Path:
        checked_output = self._output(output)
        verification_output = self._output(checked_output / "run")
        checked_baseline = self._input(baseline)
        checked_candidate = self._input(candidate)
        artifact = load_sealed_policy(self._input(sealed_policy))
        session = (
            load_edit_session(self._directory_input(session_path), trust_store=self.trust_store)
            if session_path
            else None
        )
        if artifact.authorization is not None and session is None:
            raise SessionError("verified policy verification requires --session")
        if session is not None:
            checked_candidate = claim_verified_candidate(checked_candidate, session)
            if session.baseline_sha256 != sha256_file(checked_baseline):
                raise SessionError("session baseline does not match verification baseline")
        run = verify_contract_change(
            checked_baseline,
            checked_candidate,
            artifact.frozen,
            verification_output,
            options=options,
        )
        assurance = (
            BundleAssurance.VERIFIED
            if artifact.authorization is not None
            else BundleAssurance.LOCAL
        )
        return write_review_bundle(
            run,
            artifact.frozen,
            destination=checked_output,
            assurance=assurance,
            policy_authorization=artifact.authorization,
            session_event=session.events[0] if session is not None else None,
            manifest_signer=self.manifest_signer,
        )

    def verify_local_change(
        self,
        baseline: Path,
        candidate: Path,
        sealed_policy: Path,
        output: Path,
        options: VerificationOptions,
    ) -> Path:
        """Verify a local policy after exactly one authorization-free artifact load."""
        artifact = load_sealed_policy(self._input(sealed_policy))
        return self.verify_local_change_from_artifact(
            baseline, candidate, artifact, output, options
        )

    def verify_local_change_from_artifact(
        self,
        baseline: Path,
        candidate: Path,
        artifact: SealedPolicyArtifact,
        output: Path,
        options: VerificationOptions,
    ) -> Path:
        """Verify from an already-loaded local artifact without reopening its path."""
        if artifact.authorization is not None:
            raise SessionError(
                "signed policies require the controlled CLI or enterprise runner; "
                "MCP has no session or manifest-signing authority"
            )
        checked_baseline = self._input(baseline)
        checked_candidate = self._input(candidate)
        checked_output = self._output(output)
        verification_output = self._output(checked_output / "run")
        run = verify_contract_change(
            checked_baseline,
            checked_candidate,
            artifact.frozen,
            verification_output,
            options=options,
        )
        return write_review_bundle(
            run,
            artifact.frozen,
            destination=checked_output,
            assurance=BundleAssurance.LOCAL,
        )

    def snapshot_generated_local_bundle(self, bundle: Path) -> GeneratedReviewBundleSnapshot:
        """Capture verified local-bundle data once, immediately after this app generated it."""
        resolved = self._output(bundle)
        verification = verify_review_bundle(resolved, trust_store=self.trust_store)
        if not verification.valid:
            raise BundleError("generated review bundle verification failed")
        if verification.currently_trusted is False:
            raise BundleError("generated review bundle trust is no longer valid")
        return GeneratedReviewBundleSnapshot(
            verification=verification,
            effective_verdict=load_effective_verdict(resolved, trust_store=self.trust_store),
            findings=tuple(list_findings(resolved)),
        )

    def requires_verified_session(self, sealed_policy: Path) -> bool:
        """Report whether a sealed policy carries a verified authorization."""
        return load_sealed_policy(self._input(sealed_policy)).authorization is not None

    def list_findings(self, bundle: Path) -> list[Finding]:
        return list_findings(self._directory_input(bundle))

    def get_finding(
        self,
        bundle: Path,
        finding_id: str,
    ) -> Finding:
        findings = [item for item in self.list_findings(bundle) if item.id == finding_id]
        if len(findings) != 1:
            from artifactdiff.errors import ApprovalError

            raise ApprovalError("finding does not exist")
        return findings[0]

    def approve(
        self, bundle: Path, finding_id: str, reason: str, *, signer: SigningProvider
    ) -> ApprovalEvent:
        return approve_finding(
            self._directory_input(bundle),
            finding_id,
            reason,
            signer=signer,
            trust_store=self.trust_store,
        )

    def verify_bundle(self, bundle: Path) -> BundleVerification:
        return verify_review_bundle(self._directory_input(bundle), trust_store=self.trust_store)

    def effective_verdict(
        self, bundle: Path, *, require_current_trust: bool = True
    ) -> EffectiveVerdict:
        """Load the fail-closed verdict after independently verifying the bundle."""
        return load_effective_verdict(
            self._directory_input(bundle),
            trust_store=self.trust_store,
            require_current_trust=require_current_trust,
        )

    def validate_event_snapshot(
        self,
        manifest: BundleManifest,
        raw: RawVerdict,
        events: tuple[ApprovalEvent, ...],
    ) -> EffectiveVerdict:
        """Validate exact event bytes already captured by a bounded adapter read."""
        return validate_approval_event_snapshot(
            manifest,
            raw,
            events,
            trust_store=self.trust_store,
        )

    def pack_bundle(
        self,
        bundle: Path,
        output: Path,
        *,
        mode: EvidenceMode,
        recipients: tuple[str, ...] = (),
        archive_signer: SigningProvider | None = None,
    ) -> Path:
        return pack_bundle(
            self._directory_input(bundle),
            self._output(output),
            mode=mode,
            recipients=recipients,
            archive_signer=archive_signer,
        )
