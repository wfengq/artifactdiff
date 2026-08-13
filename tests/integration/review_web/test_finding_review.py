from __future__ import annotations

import base64
import dataclasses
import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.bundle import write_review_bundle
from artifactdiff.cli import app as cli_app
from artifactdiff.review_web.app import ReviewContext, create_review_app
from artifactdiff.review_web.signing_provider import (
    FakeSigningProvider,
    InteractiveEd25519SigningProvider,
)
from artifactdiff.trust import SignatureEnvelope, TrustRole
from artifactdiff.verification import (
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
    finding_id,
)
from tests.review_web_client import AsgiClient

pytest_plugins = ("tests.integration.bundle.conftest",)

SESSION_TOKEN = "r" * 43
CSRF_TOKEN = "s" * 43
BASE_URL = "http://127.0.0.1:8765"


def _finding(outcome: FindingOutcome, *, approvable: bool, location: str) -> Finding:
    return Finding(
        id=finding_id(
            rule_id="contract-safe.allow",
            rule_version="1.0",
            location=location,
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
        ),
        rule_id="contract-safe.allow",
        outcome=outcome,
        location=location,
        evidence=FindingEvidence(
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
            before_excerpt='<script>alert("before")</script>',
            after_excerpt="Reviewed layout reflow",
        ),
        remediation="Review this exact finding.",
        approvable=approvable,
    )


def _bundle(bundle_fixture: object, *findings: Finding) -> Path:
    outcome = (
        FindingOutcome.FAIL
        if any(f.outcome is FindingOutcome.FAIL for f in findings)
        else FindingOutcome.REVIEW
    )
    verdict = RawVerdict(
        outcome=outcome,
        policy_sha256=bundle_fixture.frozen.canonical_sha256,
        baseline_sha256=bundle_fixture.run.facts.baseline_sha256,
        candidate_sha256=bundle_fixture.run.facts.candidate_sha256,
        findings=list(findings),
    )
    run = dataclasses.replace(bundle_fixture.run, result=verdict)
    return write_review_bundle(**{**bundle_fixture.local_args(), "run": run})


def _client(bundle_fixture: object, bundle: Path) -> tuple[AsgiClient, FakeSigningProvider]:
    application = ArtifactDiffApplication(trust_store=bundle_fixture.trust_store)
    signer = FakeSigningProvider(application, bundle_fixture.approver_signer)
    app = create_review_app(
        ReviewContext(application, "bundle", bundle, signer), SESSION_TOKEN, CSRF_TOKEN
    )
    app.state.bound_host = "127.0.0.1:8765"
    client = AsgiClient(app, base_url=BASE_URL)
    assert (
        client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN}).status_code
        == 200
    )
    return client, signer


def _headers(*, mutation: bool = False) -> dict[str, str]:
    headers = {
        "X-ArtifactDiff-Session": SESSION_TOKEN,
        "X-ArtifactDiff-CSRF": CSRF_TOKEN,
    }
    if mutation:
        headers.update({"Origin": BASE_URL, "Content-Type": "application/json"})
    return headers


def test_review_desk_paginates_findings_without_returning_source_contracts(
    bundle_fixture: object,
) -> None:
    """An unbounded review response or source payload would violate the desk privacy boundary."""
    first = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:first")
    second = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:second")
    bundle = _bundle(bundle_fixture, first, second)
    client, _ = _client(bundle_fixture, bundle)

    response = client.get("/api/findings?cursor=1&limit=1", headers=_headers())

    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == [second.id]
    assert response.json()["next_cursor"] is None
    encoded = response.text
    assert "C:/private/customer" not in encoded
    assert "BEGIN PRIVATE KEY" not in encoded


def test_review_desk_approves_one_finding_and_updates_effective_verdict(
    bundle_fixture: object,
) -> None:
    """A signed per-finding approval must be appended server-side and recompute the verdict."""
    finding = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:review")
    bundle = _bundle(bundle_fixture, finding)
    client, signer = _client(bundle_fixture, bundle)

    result = client.post(
        "/api/approvals",
        headers=_headers(mutation=True),
        json={
            "finding_id": finding.id,
            "reason": "Layout reflow reviewed against the signed instruction",
        },
    )

    assert result.status_code == 200
    assert result.json()["event"]["finding_id"] == finding.id
    assert result.json()["effective_verdict"]["outcome"] == "pass"
    assert result.json()["state"] == "approval-complete"
    assert signer.approval_calls == [(bundle, finding.id)]
    assert "private_key" not in result.text and "passphrase" not in result.text


def test_fail_finding_has_no_approval_capability(bundle_fixture: object) -> None:
    """Fail findings require a corrected candidate or policy and can never be approved."""
    finding = _finding(FindingOutcome.FAIL, approvable=False, location="clause:fail")
    bundle = _bundle(bundle_fixture, finding)
    client, signer = _client(bundle_fixture, bundle)

    detail = client.get(f"/api/findings/{finding.id}", headers=_headers())
    refused = client.post(
        "/api/approvals",
        headers=_headers(mutation=True),
        json={"finding_id": finding.id, "reason": "Accept anyway"},
    )

    assert detail.status_code == 200
    assert detail.json()["approval_enabled"] is False
    assert refused.status_code == 409
    assert signer.approval_calls == []


def test_bundle_summary_exposes_assurance_trust_and_raw_effective_verdict(
    bundle_fixture: object,
) -> None:
    """Minimizing assurance or hiding a blocking effective verdict could mislead a reviewer."""
    finding = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:summary")
    bundle = _bundle(bundle_fixture, finding)
    client, _ = _client(bundle_fixture, bundle)

    response = client.get("/api/bundle", headers=_headers())

    assert response.status_code == 200
    payload = response.json()
    assert payload["assurance"] == "local"
    assert payload["raw_verdict"] == "review"
    assert payload["effective_verdict"]["outcome"] == "review"
    assert payload["state"] == "bundle-review"
    assert "signature_status" in payload and "event_history" in payload


def test_findings_endpoint_refuses_a_tampered_bundle_before_returning_evidence(
    bundle_fixture: object,
) -> None:
    """Direct finding navigation must not bypass the immutable bundle verification boundary."""
    finding = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:tampered")
    bundle = _bundle(bundle_fixture, finding)
    verdict = bundle / "core" / "verdict.json"
    verdict.chmod(stat.S_IREAD | stat.S_IWRITE)
    payload = json.loads(verdict.read_text(encoding="utf-8"))
    payload["findings"][0]["evidence"]["before_excerpt"] = "TAMPERED EVIDENCE"
    verdict.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    client, _ = _client(bundle_fixture, bundle)

    response = client.get("/api/findings?cursor=0&limit=20", headers=_headers())

    assert response.status_code == 409
    assert "alert" not in response.text


def test_review_cli_starts_the_bundle_desk_with_no_open_for_automation(
    bundle_fixture: object, monkeypatch
) -> None:
    """Leaving the CLI stub in place would make the authenticated review routes unreachable."""
    finding = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:cli")
    bundle = _bundle(bundle_fixture, finding)
    captured: list[tuple[object, bool]] = []

    class Thread:
        def join(self) -> None:
            return None

    class Server:
        thread = Thread()

        def shutdown(self) -> None:
            return None

    def serve(context: object, *, open_browser: bool) -> Server:
        captured.append((context, open_browser))
        return Server()

    monkeypatch.setattr("artifactdiff.review_web.server.serve_review", serve)
    result = CliRunner().invoke(cli_app, ["review", str(bundle), "--no-open"])

    assert result.exit_code == 0, result.output
    assert len(captured) == 1 and captured[0][1] is False
    context = captured[0][0]
    assert context.mode == "bundle" and context.target_path == bundle


def test_review_cli_accepts_a_trust_store_without_enabling_signing(
    bundle_fixture: object, tmp_path: Path, monkeypatch
) -> None:
    """Read-only verification of signed bundles must not require access to a private key."""
    finding = _finding(FindingOutcome.REVIEW, approvable=True, location="clause:readonly")
    bundle = _bundle(bundle_fixture, finding)
    store = tmp_path / "trust.json"
    store.write_text(bundle_fixture.trust_store.model_dump_json(), encoding="utf-8")
    captured: list[object] = []

    class Thread:
        def join(self) -> None:
            return None

    class Server:
        thread = Thread()

        def shutdown(self) -> None:
            return None

    def serve(context: object, *, open_browser: bool) -> Server:
        del open_browser
        captured.append(context)
        return Server()

    monkeypatch.setattr("artifactdiff.review_web.server.serve_review", serve)
    result = CliRunner().invoke(
        cli_app,
        ["review", str(bundle), "--no-open", "--trust-store", str(store)],
    )

    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0].signing_provider is None


def test_interactive_signer_erases_its_scoped_passphrase_buffer(
    bundle_fixture: object, monkeypatch
) -> None:
    """Retaining the mutable passphrase after signing would extend secret lifetime server-side."""
    application = ArtifactDiffApplication(trust_store=bundle_fixture.trust_store)
    captured: list[object] = []

    class LowLevelSigner:
        def __init__(self, _identity, _path, secret, _store) -> None:
            captured.append(secret)
            self.secret = secret

        def sign(self, *, purpose: str, digest: str, required_role: TrustRole) -> SignatureEnvelope:
            assert self.secret.get_secret("identity") == b"correct horse battery staple"
            assert required_role is TrustRole.POLICY_AUTHORIZER
            return SignatureEnvelope(
                public_key_fingerprint="a" * 64,
                identity="policy-authorizer",
                purpose=purpose,
                canonical_object_sha256=digest,
                signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
            )

    monkeypatch.setattr(
        "artifactdiff.review_web.signing_provider.getpass.getpass",
        lambda _prompt: "correct horse battery staple",
    )
    monkeypatch.setattr(
        "artifactdiff.review_web.signing_provider.LocalEd25519SigningProvider", LowLevelSigner
    )
    provider = InteractiveEd25519SigningProvider(
        application,
        "policy-authorizer",
        Path("encrypted-key.pem"),
        bundle_fixture.trust_store,
    )

    authorization = provider.sign_policy(bundle_fixture.frozen)

    assert authorization.signature.purpose == "policy_authorization"
    assert len(captured) == 1
    assert set(captured[0].buffer) == {0}
    assert "correct horse battery staple" not in authorization.model_dump_json()
