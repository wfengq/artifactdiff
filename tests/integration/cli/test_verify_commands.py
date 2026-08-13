import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from reportlab.pdfgen.canvas import Canvas
from typer.testing import CliRunner

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli import app
from artifactdiff.cli_support import _PromptSecret
from artifactdiff.contract import ClauseSelector
from artifactdiff.session import SealedPolicyArtifact, authorize_policy, write_sealed_policy
from artifactdiff.trust import (
    TrustIdentity,
    TrustRole,
    TrustStore,
    generate_private_key,
    sign_digest,
)
from tests.factories import make_docx

runner = CliRunner()


def test_review_is_a_discoverable_lazy_adapter_boundary() -> None:
    """Replacing the deferred desk boundary with a traceback leaks implementation state."""
    result = runner.invoke(app, ["review", "--no-open"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "not available" in result.stderr


def test_private_key_prompt_is_directed_to_stderr_for_json_commands(monkeypatch) -> None:
    """Writing an interactive signing prompt to stdout corrupts a JSON response stream."""
    observed: dict[str, object] = {}

    monkeypatch.setattr("artifactdiff.cli_support.sys.stdin.isatty", lambda: True)

    def prompt(_text: str, **kwargs: object) -> str:
        observed.update(kwargs)
        return "passphrase"

    monkeypatch.setattr("artifactdiff.cli_support.typer.prompt", prompt)

    assert _PromptSecret().get_secret("archive") == b"passphrase"
    assert observed["err"] is True


def _sealed_exact_policy(baseline, root):
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="",
            heading="",
            anchor="Payment is due within 30 days.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, root / "policy.json")
    return application.seal_policy(baseline, policy_path, root / "sealed.json")


def _pdf(path, lines, *, y_origin: int = 720):
    canvas = Canvas(str(path))
    for offset, line in enumerate(lines):
        canvas.drawString(72, y_origin - 20 * offset, line)
    canvas.save()
    return path


def test_verify_exit_codes_follow_effective_verdict(tmp_path) -> None:
    """Returning zero for a review or fail finding would allow an unsafe change through CI."""
    baseline = _pdf(tmp_path / "baseline.pdf", ["Payment Terms", "Payment is due within 30 days."])
    exact = _pdf(tmp_path / "exact.pdf", ["Payment Terms", "Payment is due within 45 days."])
    reflow = _pdf(
        tmp_path / "reflow.pdf",
        ["Payment Terms", "Payment is due within 45 days."],
        y_origin=680,
    )
    party_change = _pdf(
        tmp_path / "party-change.pdf",
        ["Payment Terms", "Acme Corporation agrees payment is due within 45 days."],
    )
    sealed = _sealed_exact_policy(baseline, tmp_path)

    passing = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(exact),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "exact-bundle"),
        ],
    )
    failing = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(party_change),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "party-bundle"),
        ],
    )
    review = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(reflow),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "reflow-bundle"),
        ],
    )

    assert passing.exit_code == 0, passing.stderr
    assert review.exit_code == 1, review.stderr
    assert failing.exit_code == 1, failing.stderr


@pytest.mark.parametrize("case", ["local", "bad-signature", "wrong-baseline", "wrong-signer-role"])
def test_session_open_rejects_invalid_verified_session_inputs_without_creating_workspace(
    bundle_fixture: object, tmp_path, case: str
) -> None:
    """Opening a workspace for an invalid policy, baseline, or signer would bypass session controls."""
    baseline = tmp_path / "baseline.docx"
    baseline.write_bytes(b"different baseline")
    policy = tmp_path / "sealed.json"
    authorization = bundle_fixture.authorization
    if case == "bad-signature":
        authorization = authorization.model_copy(
            update={
                "signature": authorization.signature.model_copy(
                    update={"signature_base64": "B" + authorization.signature.signature_base64[1:]}
                )
            }
        )
    artifact = SealedPolicyArtifact(
        frozen=bundle_fixture.frozen,
        authorization=None if case == "local" else authorization,
    )
    write_sealed_policy(artifact, policy)
    trust_store = tmp_path / "trust.json"
    trust_store.write_text(bundle_fixture.trust_store.model_dump_json(), encoding="utf-8")
    output = tmp_path / "sessions"
    output.mkdir()
    identity = (
        "bundle-policy-authorizer" if case == "wrong-signer-role" else "bundle-archive-signer"
    )

    result = runner.invoke(
        app,
        [
            "session",
            "open",
            str(baseline),
            "--policy",
            str(policy),
            "--output",
            str(output),
            "--sign",
            identity,
            "--key",
            str(tmp_path / "missing.pem"),
            "--trust-store",
            str(trust_store),
        ],
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert list(output.iterdir()) == []


def _identity(key: Ed25519PrivateKey, identity: str, role: TrustRole) -> TrustIdentity:
    public = key.public_key()
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return TrustIdentity(
        id=identity,
        subject_type="human" if role is TrustRole.POLICY_AUTHORIZER else "service",
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        public_key_pem=public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii"),
        roles=frozenset({role}),
    )


def test_verified_verify_json_is_one_stdout_document(tmp_path, monkeypatch) -> None:
    """A signing prompt on stdout would make verified automation JSON unparsable."""
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    baseline = make_docx(
        inputs / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    authorizer_key = Ed25519PrivateKey.generate()
    archive_key = Ed25519PrivateKey.generate()
    authorizer = _identity(authorizer_key, "policy-authorizer", TrustRole.POLICY_AUTHORIZER)
    archive = _identity(archive_key, "archive-signer", TrustRole.ARCHIVE_SIGNER)
    store = TrustStore(identities=[authorizer, archive])
    application = ArtifactDiffApplication(trust_store=store)
    draft = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="", heading="Payment Terms", anchor="Payment is due within 30 days."
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(draft, inputs / "policy.json")

    class Authorizer:
        def sign(self, *, purpose: str, digest: str, required_role: TrustRole):
            assert required_role is TrustRole.POLICY_AUTHORIZER
            return sign_digest(authorizer_key, identity=authorizer, purpose=purpose, digest=digest)

    frozen = application.seal_policy(baseline, policy_path, inputs / "local.json")
    from artifactdiff.session import load_sealed_policy

    artifact = load_sealed_policy(frozen)
    authorization = authorize_policy(artifact.frozen, signer=Authorizer())
    sealed = write_sealed_policy(
        SealedPolicyArtifact(frozen=artifact.frozen, authorization=authorization),
        inputs / "sealed.json",
    )
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(store.model_dump_json(), encoding="utf-8")
    key_path = tmp_path / "archive.pem"

    class Secret:
        def get_secret(self, _identity: str) -> bytes:
            return b"passphrase"

    generate_private_key(key_path, identity="archive-signer", secret_provider=Secret())
    # Replace generated key with the archive identity's encrypted key so the CLI can sign its manifest.
    key_path.write_bytes(
        archive_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"passphrase"),
        )
    )
    monkeypatch.setattr("typer.testing._NamedTextIOWrapper.isatty", lambda _self: True)
    monkeypatch.setattr(
        "artifactdiff.cli_support.typer.prompt", lambda *_args, **_kwargs: "passphrase"
    )
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    session_root = outputs / "session-root"
    session_root.mkdir()
    opened = runner.invoke(
        app,
        [
            "session",
            "open",
            str(baseline),
            "--policy",
            str(sealed),
            "--output",
            str(session_root),
            "--sign",
            "archive-signer",
            "--key",
            str(key_path),
            "--trust-store",
            str(trust_path),
        ],
    )

    assert opened.exit_code == 0, opened.output
    candidate = Path(opened.stdout.splitlines()[0])
    from docx import Document

    document = Document(candidate)
    document.paragraphs[1].text = "Payment is due within 45 days."
    document.save(candidate)
    session = Path(opened.stdout.splitlines()[1])
    result = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(candidate),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "bundle"),
            "--session",
            str(session_root / "sessions" / session),
            "--archive-sign",
            "archive-signer",
            "--archive-key",
            str(key_path),
            "--trust-store",
            str(trust_path),
            "--json",
        ],
    )

    assert result.exit_code in {0, 1}, result.stderr
    payload = json.loads(result.stdout)
    assert set(payload) == {"bundle", "verification"}
