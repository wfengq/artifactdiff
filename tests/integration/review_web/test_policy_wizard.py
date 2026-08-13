from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli import app as cli_app
from artifactdiff.contract import ClauseSelector
from artifactdiff.policy import ContractPolicy, canonical_policy_bytes
from artifactdiff.review_web.app import ReviewContext, create_review_app
from artifactdiff.trust import TrustStore
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
    client = _client(baseline)
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
