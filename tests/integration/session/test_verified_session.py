from __future__ import annotations

import hashlib
import json
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from artifactdiff.contract import (
    ClauseLabel,
    ClauseSelector,
    ContractClause,
    ContractDocument,
    LanguageKind,
    LanguageProfile,
)
from artifactdiff.errors import SessionError, SignatureError
from artifactdiff.fs_safety import PathPolicy
from artifactdiff.models import SourceDescriptor
from artifactdiff.normalize import fingerprint, normalize_text
from artifactdiff.policy import draft_exact_replace_policy, freeze_policy
from artifactdiff.session import (
    SealedPolicyArtifact,
    authorize_policy,
    claim_verified_candidate,
    load_edit_session,
    load_sealed_policy,
    open_verified_edit_session,
    write_sealed_policy,
)
from artifactdiff.trust import (
    PolicyAuthorization,
    SignatureEnvelope,
    TrustIdentity,
    TrustRole,
    TrustStore,
    sign_digest,
)


@dataclass(frozen=True, slots=True)
class MemorySigner:
    private_key: Ed25519PrivateKey
    identity: TrustIdentity
    include_unverified_time_evidence: bool = False

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
            trusted_time={"source": "unverified"}
            if self.include_unverified_time_evidence
            else None,
        )


@dataclass(frozen=True, slots=True)
class SessionFixture:
    baseline: Path
    root: Path
    frozen: object
    authorization: PolicyAuthorization
    trust_store: TrustStore
    session_signer: MemorySigner
    path_policy: PathPolicy

    def valid_args(self) -> dict[str, object]:
        return {
            "baseline": self.baseline,
            "frozen": self.frozen,
            "authorization": self.authorization,
            "root": self.root,
            "trust_store": self.trust_store,
            "session_signer": self.session_signer,
            "path_policy": self.path_policy,
        }


def _symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")


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
def session_fixture(tmp_path: Path) -> SessionFixture:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    baseline = input_root / "contract.docx"
    baseline.write_bytes(b"ArtifactDiff controlled contract baseline\n")

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

    authorizer_key = Ed25519PrivateKey.generate()
    archive_key = Ed25519PrivateKey.generate()
    authorizer = _identity(
        authorizer_key,
        identity="policy-authorizer",
        role=TrustRole.POLICY_AUTHORIZER,
    )
    archive_signer = _identity(
        archive_key,
        identity="session-archive",
        role=TrustRole.ARCHIVE_SIGNER,
    )
    authorizer_provider = MemorySigner(authorizer_key, authorizer)
    authorization = authorize_policy(frozen, signer=authorizer_provider)
    return SessionFixture(
        baseline=baseline,
        root=output_root,
        frozen=frozen,
        authorization=authorization,
        trust_store=TrustStore(identities=[authorizer, archive_signer]),
        session_signer=MemorySigner(
            archive_key,
            archive_signer,
            include_unverified_time_evidence=True,
        ),
        path_policy=PathPolicy(
            input_roots=(input_root,),
            output_roots=(output_root,),
        ),
    )


def test_verified_session_is_created_only_after_policy_signature_verifies(
    session_fixture: SessionFixture,
) -> None:
    session = open_verified_edit_session(**session_fixture.valid_args())

    assert session.assurance == "verified"
    assert session.candidate_path.read_bytes() == session_fixture.baseline.read_bytes()
    assert session.baseline_snapshot_path.read_bytes() == session_fixture.baseline.read_bytes()
    assert session.baseline_snapshot_path.stat().st_mode & stat.S_IWUSR == 0
    assert session.candidate_path.stat().st_mode & stat.S_IWUSR != 0
    assert session.events[0].event_type == "session_opened"
    assert session.events[0].chronology == "artifactdiff_controlled_session"
    assert session.events[0].trusted_time is False
    assert load_edit_session(session.root_path, trust_store=session_fixture.trust_store) == session


def test_invalid_policy_signature_creates_no_workspace(
    session_fixture: SessionFixture,
) -> None:
    bad_signature = session_fixture.authorization.signature.model_copy(
        update={"canonical_object_sha256": "f" * 64}
    )
    bad_authorization = session_fixture.authorization.model_copy(
        update={"signature": bad_signature}
    )

    with pytest.raises(SignatureError):
        open_verified_edit_session(
            **{
                **session_fixture.valid_args(),
                "authorization": bad_authorization,
            }
        )

    assert list(session_fixture.root.iterdir()) == []


def test_wrong_baseline_leaves_no_completed_or_temporary_session(
    session_fixture: SessionFixture,
) -> None:
    session_fixture.baseline.write_bytes(b"different contract bytes\n")

    with pytest.raises(SessionError):
        open_verified_edit_session(**session_fixture.valid_args())

    assert not any(path.name.endswith(".tmp") for path in session_fixture.root.rglob("*"))
    assert not any(
        path.is_dir() and (path / "session.json").exists()
        for path in session_fixture.root.rglob("*")
    )


@pytest.mark.parametrize("stage", ["policy", "baseline", "candidate", "event", "session"])
def test_crash_after_each_stage_write_leaves_no_session(
    session_fixture: SessionFixture,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    from artifactdiff.session import service

    def fail_after_write(completed_stage: str) -> None:
        if completed_stage == stage:
            raise OSError("injected write failure")

    monkeypatch.setattr(service, "_after_stage_write", fail_after_write)

    with pytest.raises(SessionError):
        open_verified_edit_session(**session_fixture.valid_args())

    assert not any(path.name.endswith(".tmp") for path in session_fixture.root.rglob("*"))
    assert not any(
        path.is_dir() and (path / "session.json").exists()
        for path in session_fixture.root.rglob("*")
    )


def test_baseline_replacement_before_publish_aborts_the_session(
    session_fixture: SessionFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from artifactdiff.session import service

    def replace_staged_baseline(completed_stage: str) -> None:
        if completed_stage != "session":
            return
        staging = next(
            path
            for path in (session_fixture.root / "sessions").iterdir()
            if path.name.endswith(".tmp")
        )
        staged_baseline = staging / "baseline" / session_fixture.baseline.name
        staged_baseline.write_bytes(b"replaced after its first digest check\n")

    monkeypatch.setattr(service, "_after_stage_write", replace_staged_baseline)

    with pytest.raises(SessionError):
        open_verified_edit_session(**session_fixture.valid_args())

    assert not any(path.name.endswith(".tmp") for path in session_fixture.root.rglob("*"))
    assert not any(
        path.is_dir() and (path / "session.json").exists()
        for path in session_fixture.root.rglob("*")
    )


def test_claim_verified_candidate_rejects_an_external_file(
    session_fixture: SessionFixture,
    tmp_path: Path,
) -> None:
    session = open_verified_edit_session(**session_fixture.valid_args())
    external = tmp_path / "external.docx"
    external.write_bytes(b"already edited elsewhere")

    with pytest.raises(
        SessionError,
        match="verified candidates must originate in an ArtifactDiff edit session",
    ):
        claim_verified_candidate(external, session)


def test_load_edit_session_rejects_a_tampered_event(
    session_fixture: SessionFixture,
) -> None:
    session = open_verified_edit_session(**session_fixture.valid_args())
    event_path = session.root_path / "events" / "000001-session-opened.json"
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    payload["nonce_sha256"] = "0" * 64
    event_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    event_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((SessionError, SignatureError)):
        load_edit_session(session.root_path, trust_store=session_fixture.trust_store)


def test_load_edit_session_rejects_a_writable_baseline_snapshot(
    session_fixture: SessionFixture,
) -> None:
    session = open_verified_edit_session(**session_fixture.valid_args())
    session.baseline_snapshot_path.chmod(stat.S_IWRITE | stat.S_IREAD)

    with pytest.raises(SessionError):
        load_edit_session(session.root_path, trust_store=session_fixture.trust_store)


def test_load_edit_session_rejects_a_symlinked_controlled_directory(
    session_fixture: SessionFixture,
    tmp_path: Path,
) -> None:
    session = open_verified_edit_session(**session_fixture.valid_args())
    outside = tmp_path / "outside-baseline"
    outside.mkdir()
    outside_file = outside / session.baseline_snapshot_path.name
    outside_file.write_bytes(session.baseline_snapshot_path.read_bytes())
    session.baseline_snapshot_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    shutil.rmtree(session.baseline_snapshot_path.parent)
    _symlink_or_skip(session.baseline_snapshot_path.parent, outside, directory=True)

    with pytest.raises(SessionError):
        load_edit_session(session.root_path, trust_store=session_fixture.trust_store)


def test_sealed_policy_never_serializes_an_assurance_claim(
    session_fixture: SessionFixture,
    tmp_path: Path,
) -> None:
    local_path = tmp_path / "local-policy.json"
    verified_path = tmp_path / "verified-policy.json"
    local = SealedPolicyArtifact(frozen=session_fixture.frozen)
    verified = SealedPolicyArtifact(
        frozen=session_fixture.frozen,
        authorization=session_fixture.authorization,
    )

    write_sealed_policy(local, local_path)
    write_sealed_policy(verified, verified_path)

    assert "assurance" not in json.loads(local_path.read_text(encoding="utf-8"))
    assert "assurance" not in json.loads(verified_path.read_text(encoding="utf-8"))
    assert load_sealed_policy(local_path) == local
    assert load_sealed_policy(verified_path) == verified


def test_sealed_policy_rejects_a_serialized_verified_label(
    session_fixture: SessionFixture,
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.json"
    write_sealed_policy(
        SealedPolicyArtifact(
            frozen=session_fixture.frozen,
            authorization=session_fixture.authorization,
        ),
        path,
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["assurance"] = "verified"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionError):
        load_sealed_policy(path)
