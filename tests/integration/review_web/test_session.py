from __future__ import annotations

import socket
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from artifactdiff.review_web.app import ReviewContext, create_review_app
from artifactdiff.review_web.server import serve_review

SESSION_TOKEN = "a" * 43
CSRF_TOKEN = "b" * 43


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    app = create_review_app(
        ReviewContext(
            application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
        ),
        SESSION_TOKEN,
        CSRF_TOKEN,
    )
    app.state.bound_host = "127.0.0.1:8765"
    with TestClient(app, base_url="http://127.0.0.1:8765") as test_client:
        yield test_client


def session_headers() -> dict[str, str]:
    return {"X-ArtifactDiff-Session": SESSION_TOKEN, "X-ArtifactDiff-CSRF": CSRF_TOKEN}


def mutation_headers() -> dict[str, str]:
    return {
        **session_headers(),
        "Origin": "http://127.0.0.1:8765",
        "Content-Type": "application/json",
    }


def exchange(client: TestClient) -> None:
    response = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})
    assert response.status_code == 200


def test_fragment_token_exchange_returns_csrf_without_accepting_a_query_token(
    client: TestClient,
) -> None:
    """Moving the launch token to a query parameter would expose it to HTTP logs."""
    rejected = client.post("/api/session?token=" + SESSION_TOKEN)
    response = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})

    assert rejected.status_code == 403
    assert response.status_code == 200
    assert response.json() == {"csrf_token": CSRF_TOKEN}


def test_mutating_routes_require_exact_origin_and_json_content_type(client: TestClient) -> None:
    """Permitting a cross-origin or form request would make a session token CSRFable."""
    exchange(client)
    cross_origin = client.post(
        "/api/policy",
        headers={**mutation_headers(), "Origin": "http://attacker.invalid"},
        json={},
    )
    wrong_content_type = client.post(
        "/api/policy",
        headers={**session_headers(), "Origin": "http://127.0.0.1:8765"},
        content="{}",
    )
    accepted_placeholder = client.post("/api/policy", headers=mutation_headers(), json={})

    assert (
        cross_origin.status_code,
        wrong_content_type.status_code,
        accepted_placeholder.status_code,
    ) == (
        403,
        415,
        501,
    )


def test_shutdown_is_one_use_and_server_shutdown_is_idempotent(client: TestClient) -> None:
    """Reusing a shutdown capability after it succeeds must not reopen the endpoint."""
    exchange(client)
    first = client.post("/api/shutdown", headers=mutation_headers(), json={})
    second = client.post("/api/shutdown", headers=mutation_headers(), json={})

    assert (first.status_code, second.status_code) == (200, 403)


def test_server_binds_an_ipv4_loopback_socket_and_stops_without_a_child_process(
    tmp_path: Path,
) -> None:
    """Changing the listener host or leaving the server thread alive exposes the desk remotely."""
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    try:
        parsed = server.url.split("/#", maxsplit=1)[0]
        assert parsed.startswith("http://127.0.0.1:")
        assert server.socket.family == socket.AF_INET
        assert server.socket.getsockname()[0] == "127.0.0.1"
        assert server.thread.is_alive()
    finally:
        server.shutdown()
        server.shutdown()

    assert not server.thread.is_alive()


def test_authenticated_shutdown_request_stops_the_live_loopback_server(tmp_path: Path) -> None:
    """Joining the server thread from its request handler would strand the process."""
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    base_url = server.url.split("/#", maxsplit=1)[0]
    token = server.url.rsplit("=", maxsplit=1)[1]
    try:
        with httpx.Client(base_url=base_url, timeout=2.0) as live_client:
            exchange_response = live_client.post(
                "/api/session", headers={"X-ArtifactDiff-Session": token}
            )
            csrf = exchange_response.json()["csrf_token"]
            response = live_client.post(
                "/api/shutdown",
                headers={
                    "X-ArtifactDiff-Session": token,
                    "X-ArtifactDiff-CSRF": csrf,
                    "Origin": base_url,
                    "Content-Type": "application/json",
                },
                content="{}",
            )
        assert response.status_code == 200
        server.thread.join(timeout=2.0)
        assert not server.thread.is_alive()
    finally:
        server.shutdown()
