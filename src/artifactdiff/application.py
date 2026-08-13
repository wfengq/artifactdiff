"""The single public application boundary used by ArtifactDiff adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from artifactdiff.bundle import (
    BundleAssurance,
    BundleVerification,
    verify_review_bundle,
    write_review_bundle,
)
from artifactdiff.contract import ClauseSelector, ContractDocument, inspect_contract, load_contract
from artifactdiff.evidence import pack_bundle
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.normalize import sha256_file
from artifactdiff.policy import (
    ContractPolicy,
    draft_exact_replace_policy,
    freeze_policy,
    load_policy,
    validate_policy,
    write_policy,
)
from artifactdiff.policy.models import EvidenceMode
from artifactdiff.review import (
    EffectiveVerdict,
    approve_finding,
    list_findings,
    load_effective_verdict,
)
from artifactdiff.session import (
    SealedPolicyArtifact,
    claim_verified_candidate,
    load_edit_session,
    load_sealed_policy,
    open_verified_edit_session,
    write_sealed_policy,
)
from artifactdiff.trust import SigningProvider, TrustStore
from artifactdiff.verification import Finding
from artifactdiff.verification.service import VerificationOptions, verify_contract_change


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

    def write_policy(self, policy: ContractPolicy, output: Path) -> Path:
        return write_policy(policy, self._output(output))

    def validate_policy(self, baseline: Path, policy_path: Path) -> ContractPolicy:
        policy = load_policy(self._input(policy_path))
        validate_policy(self._contract(baseline), policy)
        return policy

    def seal_policy(
        self,
        baseline: Path,
        policy_path: Path,
        output: Path,
        *,
        signer: SigningProvider | None = None,
    ) -> Path:
        policy = self.validate_policy(baseline, policy_path)
        frozen = freeze_policy(self._contract(baseline), policy)
        authorization = None
        if signer is not None:
            from artifactdiff.session import authorize_policy

            authorization = authorize_policy(frozen, signer=signer)
        return write_sealed_policy(
            SealedPolicyArtifact(frozen=frozen, authorization=authorization), self._output(output)
        )

    def open_verified_session(
        self,
        baseline: Path,
        sealed_policy: Path,
        output: Path,
        *,
        session_signer: SigningProvider,
    ) -> object:
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
        from artifactdiff.errors import SessionError

        checked_baseline = self._input(baseline)
        checked_candidate = self._input(candidate)
        artifact = load_sealed_policy(self._input(sealed_policy))
        checked_output = self._output(output)
        session = (
            load_edit_session(session_path, trust_store=self.trust_store) if session_path else None
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
            checked_output / "run",
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

    def requires_verified_session(self, sealed_policy: Path) -> bool:
        """Report whether a sealed policy carries a verified authorization."""
        return load_sealed_policy(self._input(sealed_policy)).authorization is not None

    def list_findings(self, bundle: Path) -> list[Finding]:
        return list_findings(self._input(bundle))

    def get_finding(self, bundle: Path, finding_id: str) -> Finding:
        findings = [item for item in self.list_findings(bundle) if item.id == finding_id]
        if len(findings) != 1:
            from artifactdiff.errors import ApprovalError

            raise ApprovalError("finding does not exist")
        return findings[0]

    def approve(
        self, bundle: Path, finding_id: str, reason: str, *, signer: SigningProvider
    ) -> object:
        return approve_finding(
            self._input(bundle), finding_id, reason, signer=signer, trust_store=self.trust_store
        )

    def verify_bundle(self, bundle: Path) -> BundleVerification:
        return verify_review_bundle(self._input(bundle), trust_store=self.trust_store)

    def effective_verdict(self, bundle: Path) -> EffectiveVerdict:
        """Load the fail-closed verdict after independently verifying the bundle."""
        return load_effective_verdict(self._input(bundle), trust_store=self.trust_store)

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
            self._input(bundle),
            self._output(output),
            mode=mode,
            recipients=recipients,
            archive_signer=archive_signer,
        )
