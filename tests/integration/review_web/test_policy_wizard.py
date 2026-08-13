from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli import app as cli_app
from artifactdiff.contract import ClauseSelector
from artifactdiff.policy import ContractPolicy, canonical_policy_bytes, frozen_policy_digest
from artifactdiff.review_web.app import ReviewContext, create_review_app
from artifactdiff.review_web.views import SelectorRequest
from artifactdiff.session import load_sealed_policy
from artifactdiff.trust import TrustStore
from artifactdiff.trust.models import PolicyAuthorization, SignatureEnvelope
from tests.factories import make_contract_docx
from tests.review_web_client import AsgiClient

SESSION_TOKEN = "p" * 43
CSRF_TOKEN = "c" * 43
BASE_URL = "http://127.0.0.1:8765"


def _client(baseline: Path) -> AsgiClient:
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    app = create_review_app(
        ReviewContext(application, "policy", baseline, None), SESSION_TOKEN, CSRF_TOKEN
    )
    app.state.bound_host = "127.0.0.1:8765"
    client = AsgiClient(app, base_url=BASE_URL)
    assert (
        client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN}).status_code
        == 200
    )
    return client


def _headers() -> dict[str, str]:
    return {
        "X-ArtifactDiff-Session": SESSION_TOKEN,
        "X-ArtifactDiff-CSRF": CSRF_TOKEN,
        "Origin": BASE_URL,
        "Content-Type": "application/json",
    }


def _payload() -> dict[str, object]:
    return {
        "rule_id": "payment-window",
        "selector": {
            "clause_label": "Article II",
            "heading": "Payment Terms",
            "anchor": (
                "Party A: Example Ltd.; on 2026-08-04, Party A shall pay "
                "RMB 10,000.00 within 30 days with a 5% late fee."
            ),
        },
        "before": "30 days",
        "after": "45 days",
    }


def test_wizard_matches_the_application_facade_canonical_policy(tmp_path: Path) -> None:
    """A browser-specific policy builder could drift from YAML/Python canonical policy bytes."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    expected = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="Article II",
            heading="Payment Terms",
            anchor=(
                "Party A: Example Ltd.; on 2026-08-04, Party A shall pay "
                "RMB 10,000.00 within 30 days with a 5% late fee."
            ),
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )

    response = _client(baseline).post("/api/policy", headers=_headers(), json=_payload())

    assert response.status_code == 200
    actual = ContractPolicy.model_validate(response.json()["policy"])
    assert canonical_policy_bytes(actual) == canonical_policy_bytes(expected)
    assert response.json()["state"] == "policy-ready"


def test_policy_overview_never_returns_clause_or_contract_text(tmp_path: Path) -> None:
    """Listing every clause excerpt would reconstruct the source contract in the browser."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)

    response = _client(baseline).get(
        "/api/policy",
        headers={"X-ArtifactDiff-Session": SESSION_TOKEN, "X-ArtifactDiff-CSRF": CSRF_TOKEN},
    )

    assert response.status_code == 200
    encoded = response.text
    assert "Party A: Example Ltd." not in encoded
    assert "applicable law" not in encoded
    assert all(
        "excerpt" not in clause and "text" not in clause for clause in response.json()["clauses"]
    )


def test_policy_summary_discloses_every_contract_safe_relaxation(tmp_path: Path) -> None:
    """Relaxing protected data, metadata, visual, or evidence defaults must never be hidden."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    payload = {
        **_payload(),
        "protect": ["parties", "money"],
        "metadata": {"non_business_change": "ignore"},
        "visual": {"on_unavailable": "fail"},
        "evidence": {"mode": "full"},
        "required_plugins": {
            "safe-parser": {
                "version": "1.0",
                "distribution": "artifactdiff-safe-parser",
                "allow_network": False,
                "allow_model": False,
            }
        },
    }

    response = _client(baseline).post("/api/policy", headers=_headers(), json=payload)

    assert response.status_code == 200
    relaxations = response.json()["summary"]["relaxations"]
    assert {item["field"] for item in relaxations} == {
        "protect",
        "metadata.non_business_change",
        "visual.on_unavailable",
        "evidence.mode",
    }
    assert response.json()["summary"]["required_plugins"]["safe-parser"]["version"] == "1.0"


def test_policy_endpoint_rejects_untrusted_unknown_and_invalid_selector_input(
    tmp_path: Path,
) -> None:
    """Trusting browser validation would allow unknown controls or non-resolving selectors."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    client = _client(baseline)
    unknown = client.post(
        "/api/policy", headers=_headers(), json={**_payload(), "execute": "alert(1)"}
    )
    missing = client.post(
        "/api/policy",
        headers=_headers(),
        json={
            **_payload(),
            "selector": {
                "clause_label": "Article II",
                "heading": "Payment Terms",
                "anchor": "not present",
            },
        },
    )

    assert unknown.status_code == 422
    assert missing.status_code == 422
    assert "not present" not in missing.text


def test_local_seal_returns_only_the_public_sealed_artifact(tmp_path: Path) -> None:
    """A seal response must not expose server state, baseline content, or key material."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    output = tmp_path / "sealed-policy.json"
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    app = create_review_app(
        ReviewContext(application, "policy", baseline, None, output), SESSION_TOKEN, CSRF_TOKEN
    )
    app.state.bound_host = "127.0.0.1:8765"
    client = AsgiClient(app, base_url=BASE_URL)
    assert (
        client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN}).status_code
        == 200
    )
    drafted = client.post("/api/policy", headers=_headers(), json=_payload())

    sealed = client.post(
        "/api/policy/seal",
        headers=_headers(),
        json={"assurance": "local"},
    )

    assert drafted.status_code == 200
    assert sealed.status_code == 200
    assert sealed.json()["artifact"]["authorization"] is None
    assert (
        sealed.json()["artifact"]["frozen"]["canonical_sha256"]
        == drafted.json()["summary"]["canonical_sha256"]
    )
    assert "private_key" not in sealed.text and "passphrase" not in sealed.text
    assert output.exists()
    assert (
        json.loads(output.read_text(encoding="utf-8"))["frozen"]["canonical_sha256"]
        == drafted.json()["summary"]["canonical_sha256"]
    )


def test_verified_wizard_seal_durably_writes_an_authorized_artifact(tmp_path: Path) -> None:
    """A verified choice must produce a sealed artifact, not an unsigned draft."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    output = tmp_path / "verified-policy.json"

    class Provider:
        def sign_policy(self, frozen):
            digest = frozen_policy_digest(frozen)
            return PolicyAuthorization(
                frozen_policy_sha256=digest,
                signature=SignatureEnvelope(
                    public_key_fingerprint="f" * 64,
                    identity="test-authorizer",
                    purpose="policy_authorization",
                    canonical_object_sha256=digest,
                    signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
                ),
            )

        def sign_approval(self, *_args, **_kwargs):  # pragma: no cover - protocol-only
            raise AssertionError("not used")

    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    app = create_review_app(
        ReviewContext(application, "policy", baseline, Provider(), output),
        SESSION_TOKEN,
        CSRF_TOKEN,
    )
    app.state.bound_host = "127.0.0.1:8765"
    client = AsgiClient(app, base_url=BASE_URL)
    assert (
        client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN}).status_code
        == 200
    )
    assert client.post("/api/policy", headers=_headers(), json=_payload()).status_code == 200

    sealed = client.post("/api/policy/seal", headers=_headers(), json={"assurance": "verified"})

    assert sealed.status_code == 200
    assert load_sealed_policy(output).authorization is not None


def test_policy_request_rejects_oversized_body_and_selector_collections(tmp_path: Path) -> None:
    """Browser JSON must be bounded before parsing and before selector resolution."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    client = _client(baseline)
    oversized = client.post("/api/policy", headers=_headers(), content=b"{" + b" " * 70000 + b"}")
    payload = _payload()
    payload["selector"] = {**payload["selector"], "ancestor_path": ["x"] * 33}
    too_many = client.post("/api/policy", headers=_headers(), json=payload)

    assert oversized.status_code == 413
    assert too_many.status_code == 422


def test_static_assets_are_offline_accessible_and_use_no_html_insertion(tmp_path: Path) -> None:
    """Remote dependencies or innerHTML would leak data or execute finding text."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    client = _client(baseline)
    shell = client.get("/").text
    script = client.get("/assets/app.js").text
    styles = client.get("/assets/styles.css").text
    combined = shell + script + styles

    assert "http://" not in combined and "https://" not in combined
    assert "innerHTML" not in script and "eval(" not in script
    assert "textContent" in script
    assert 'aria-live="polite"' in shell
    assert "Previous finding" in shell and "Next finding" in shell
    assert 'id="event-history-status"' in shell
    assert 'id="load-more-events"' in shell
    assert "page.items" in script and "page.truncated" in script
    assert "event_cursor=${nextEventCursor}" in script


def test_interactive_policy_create_opens_wizard_unless_no_open_is_set(
    tmp_path: Path, monkeypatch
) -> None:
    """Prompting by default would bypass the approved visual relaxation disclosure."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    output = tmp_path / "policy.json"
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
        context.output_path.write_bytes(b"sealed")
        return Server()

    monkeypatch.setattr("typer.testing._NamedTextIOWrapper.isatty", lambda _self: True)
    monkeypatch.setattr("artifactdiff.review_web.server.serve_review", serve)
    result = CliRunner().invoke(
        cli_app, ["policy", "create", str(baseline), "--output", str(output)]
    )

    assert result.exit_code == 0, result.output
    assert len(captured) == 1 and captured[0][1] is True
    context = captured[0][0]
    assert context.mode == "policy" and context.target_path == baseline
    assert context.output_path == output


def test_interactive_policy_create_fails_if_wizard_closes_without_sealing(
    tmp_path: Path, monkeypatch
) -> None:
    """CLI success must mean the requested sealed artifact was durably produced."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    output = tmp_path / "missing.json"

    class Thread:
        def join(self) -> None:
            return None

    class Server:
        thread = Thread()

        def shutdown(self) -> None:
            return None

    monkeypatch.setattr("typer.testing._NamedTextIOWrapper.isatty", lambda _self: True)
    monkeypatch.setattr(
        "artifactdiff.review_web.server.serve_review", lambda *_args, **_kwargs: Server()
    )

    result = CliRunner().invoke(cli_app, ["policy", "create", str(baseline), "-o", str(output)])

    assert result.exit_code == 2
    assert not output.exists()


def test_interactive_policy_create_configures_verified_signing_provider(
    tmp_path: Path, monkeypatch
) -> None:
    """The first-party verified wizard choice must have a server-side signing provider."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    output = tmp_path / "sealed.json"
    store = tmp_path / "trust.json"
    store.write_text('{"schema_version":"1.0","identities":[]}', encoding="utf-8")
    key = tmp_path / "key.pem"
    captured = []

    class Thread:
        def join(self) -> None:
            return None

    class Server:
        thread = Thread()

        def shutdown(self) -> None:
            return None

    def serve(context, **_kwargs):
        captured.append(context)
        context.output_path.write_bytes(b"sealed")
        return Server()

    monkeypatch.setattr("typer.testing._NamedTextIOWrapper.isatty", lambda _self: True)
    monkeypatch.setattr("artifactdiff.review_web.server.serve_review", serve)

    result = CliRunner().invoke(
        cli_app,
        [
            "policy",
            "create",
            str(baseline),
            "-o",
            str(output),
            "--sign",
            "authorizer",
            "--key",
            str(key),
            "--trust-store",
            str(store),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured[0].signing_provider is not None


def test_noninteractive_signing_intent_never_writes_an_unsigned_draft(tmp_path: Path) -> None:
    """Full selector arguments plus signing flags must not silently bypass verified sealing."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    output = tmp_path / "policy.json"
    trust = tmp_path / "trust.json"
    trust.write_text('{"schema_version":"1.0","identities":[]}', encoding="utf-8")
    result = CliRunner().invoke(
        cli_app,
        [
            "policy",
            "create",
            str(baseline),
            "-o",
            str(output),
            "--rule-id",
            "payment-window",
            "--clause",
            "Article II",
            "--heading",
            "Payment Terms",
            "--anchor",
            _payload()["selector"]["anchor"],
            "--before",
            "30 days",
            "--after",
            "45 days",
            "--sign",
            "authorizer",
            "--key",
            str(tmp_path / "key.pem"),
            "--trust-store",
            str(trust),
        ],
    )

    assert result.exit_code == 2
    assert not output.exists()


def test_selector_rejects_one_oversized_ancestor_string(tmp_path: Path) -> None:
    """A short ancestor list must not carry one unbounded string through normalization."""
    baseline = make_contract_docx(tmp_path / "baseline.docx", language="en", payment_days=30)
    payload = _payload()
    payload["selector"] = {**payload["selector"], "ancestor_path": ["x" * 513]}

    with pytest.raises(ValidationError):
        SelectorRequest.model_validate(payload["selector"])

    response = _client(baseline).post("/api/policy", headers=_headers(), json=payload)
    assert response.status_code == 422
