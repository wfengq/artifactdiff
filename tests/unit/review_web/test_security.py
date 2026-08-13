from __future__ import annotations

from pathlib import Path
from subprocess import run

import pytest
from starlette.responses import Response

import artifactdiff.review_web.app as review_app
from artifactdiff.review_web.app import ReviewContext, create_review_app
from tests.review_web_client import AsgiClient

SESSION_TOKEN = "a" * 43
CSRF_TOKEN = "b" * 43
LOOPBACK_ORIGIN = "http://127.0.0.1:8765"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


@pytest.fixture
def client(tmp_path: Path) -> AsgiClient:
    app = create_review_app(
        ReviewContext(
            application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
        ),
        SESSION_TOKEN,
        CSRF_TOKEN,
    )
    app.state.bound_host = "127.0.0.1:8765"
    yield AsgiClient(app, base_url=LOOPBACK_ORIGIN)


def assert_security_headers(response: object) -> None:
    headers = response.headers  # type: ignore[attr-defined]
    assert headers["content-security-policy"] == CSP
    assert headers["cache-control"] == "no-store"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cross-origin-resource-policy"] == "same-origin"


def test_shell_contains_no_sensitive_data_and_sets_strict_headers(client: AsgiClient) -> None:
    """Dropping a source, credential, or a security header from the shell is unsafe."""
    response = client.get("/")

    assert response.status_code == 200
    assert "SECRET CONTRACT TERM" not in response.text
    assert "BEGIN PRIVATE KEY" not in response.text
    assert_security_headers(response)


def test_classic_bootstrap_script_executes_and_reports_missing_fragment_token() -> None:
    """A top-level await in a classic script prevents every browser bootstrap from running."""
    asset = Path(review_app.__file__).with_name("assets") / "app.js"
    program = """
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(process.argv[1], "utf8");
const status = { textContent: "", setAttribute() {} };
const context = {
  URLSearchParams, location: { hash: "", pathname: "/" },
  history: { replaceState() {} },
  document: { getElementById() { return status; } },
  fetch() { throw new Error("fetch must not run without a token"); },
  console,
};
vm.runInNewContext(source, context);
setImmediate(() => {
  if (status.textContent !== "Unable to connect to the local review desk.") process.exit(1);
});
"""

    result = run(["node", "-e", program, str(asset)], capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr


def test_bootstrap_does_not_parse_a_failed_session_exchange_as_json() -> None:
    """Calling json() on an HTML 403 hides the connection failure and rejects bootstrap."""
    asset = Path(review_app.__file__).with_name("assets") / "app.js"
    program = """
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(process.argv[1], "utf8");
const status = { textContent: "", setAttribute() {} };
let parsed = false;
const context = {
  URLSearchParams, location: { hash: "#token=" + "a".repeat(43), pathname: "/" },
  history: { replaceState() {} },
  document: { getElementById() { return status; } },
  fetch() { return Promise.resolve({ ok: false, json() { parsed = true; throw new Error("no json"); } }); },
  console,
};
vm.runInNewContext(source, context);
setTimeout(() => {
  if (parsed || status.textContent !== "Unable to connect to the local review desk.") process.exit(1);
}, 20);
"""

    result = run(["node", "-e", program, str(asset)], capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr


def test_stale_finding_response_cannot_replace_detail_or_approval_target() -> None:
    """Out-of-order detail fetches must not approve a finding different from the rendered one."""
    asset = Path(review_app.__file__).with_name("assets") / "app.js"
    source = asset.read_text(encoding="utf-8")
    assert "selectionGeneration" in source
    assert "renderedFindingId" in source
    assert "findings[selected].id" not in source


@pytest.mark.parametrize("path", ["/assets/app.js", "/assets/styles.css", "/not-a-route"])
def test_assets_and_errors_receive_the_same_security_headers(client: AsgiClient, path: str) -> None:
    """A missed static or error response would leave an exploitable weak response."""
    response = client.get(path)

    assert response.status_code in {200, 404}
    assert "SECRET CONTRACT TERM" not in response.text
    assert_security_headers(response)


def test_unexpected_errors_retain_security_headers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An error handler outside the security layer would emit an unsafe 500 response."""
    app = create_review_app(
        ReviewContext(
            application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
        ),
        SESSION_TOKEN,
        CSRF_TOKEN,
    )
    app.state.bound_host = "127.0.0.1:8765"

    def broken_asset(_: str, __: str) -> Response:
        raise RuntimeError("test error")

    monkeypatch.setattr(review_app, "_asset_response", broken_asset)
    error_client = AsgiClient(app, base_url=LOOPBACK_ORIGIN, raise_server_exceptions=False)
    response = error_client.get("/")

    assert response.status_code == 500
    assert_security_headers(response)


@pytest.mark.parametrize(
    "host",
    [
        "localhost:8765",
        "[::1]:8765",
        "127.0.0.1.:8765",
        "user@127.0.0.1:8765",
        "127.0.0.1:8766",
    ],
)
def test_host_must_match_the_bound_ipv4_loopback_address(client: AsgiClient, host: str) -> None:
    """Accepting an alias, an IPv6 address, or another port defeats the local boundary."""
    response = client.get("/", headers={"Host": host})

    assert response.status_code == 400
    assert_security_headers(response)


def test_forwarded_headers_are_rejected_even_with_the_correct_host(client: AsgiClient) -> None:
    """Trusting proxy-supplied origin information could bypass direct loopback validation."""
    response = client.get("/", headers={"Forwarded": "host=attacker.invalid"})

    assert response.status_code == 400
    assert_security_headers(response)


def test_api_route_is_unavailable_without_both_exchanged_tokens(client: AsgiClient) -> None:
    """A placeholder must not become an unauthenticated data endpoint in Task 4."""
    no_tokens = client.get("/api/policy")
    missing_csrf = client.get("/api/policy", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})
    exchange = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})
    complete = client.get(
        "/api/policy",
        headers={"X-ArtifactDiff-Session": SESSION_TOKEN, "X-ArtifactDiff-CSRF": CSRF_TOKEN},
    )

    assert exchange.status_code == 200
    assert (no_tokens.status_code, missing_csrf.status_code, complete.status_code) == (
        403,
        403,
        501,
    )
    assert_security_headers(no_tokens)
    assert_security_headers(missing_csrf)
    assert_security_headers(complete)
