from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import httpx
import pytest

from artifactdiff.review_web.app import ReviewContext, create_review_app
from artifactdiff.review_web.server import ReviewServer, serve_review
from tests.review_web_client import AsgiClient

SESSION_TOKEN = "a" * 43
CSRF_TOKEN = "b" * 43


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
    yield AsgiClient(app, base_url="http://127.0.0.1:8765")


def session_headers() -> dict[str, str]:
    return {"X-ArtifactDiff-Session": SESSION_TOKEN, "X-ArtifactDiff-CSRF": CSRF_TOKEN}


def mutation_headers() -> dict[str, str]:
    return {
        **session_headers(),
        "Origin": "http://127.0.0.1:8765",
        "Content-Type": "application/json",
    }


def exchange(client: AsgiClient) -> None:
    response = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})
    assert response.status_code == 200


def test_fragment_token_exchange_returns_csrf_without_accepting_a_query_token(
    client: AsgiClient,
) -> None:
    """Moving the launch token to a query parameter would expose it to HTTP logs."""
    rejected = client.post("/api/session?token=" + SESSION_TOKEN)
    response = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})

    assert rejected.status_code == 403
    assert response.status_code == 200
    assert response.json() == {"csrf_token": CSRF_TOKEN}


def test_session_exchange_consumes_the_fragment_token_once(client: AsgiClient) -> None:
    """Replaying the fragment token must not reveal the CSRF capability again."""
    first = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})
    replay = client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})

    assert first.status_code == 200
    assert replay.status_code == 403
    assert replay.text == "forbidden"


def test_session_and_csrf_failures_are_uniform(client: AsgiClient) -> None:
    """Different token failures must not disclose which capability was accepted."""
    missing_session = client.get("/api/policy")
    exchange(client)
    missing_csrf = client.get("/api/policy", headers={"X-ArtifactDiff-Session": SESSION_TOKEN})
    invalid_session = client.get(
        "/api/policy",
        headers={"X-ArtifactDiff-Session": "c" * 43, "X-ArtifactDiff-CSRF": CSRF_TOKEN},
    )
    invalid_csrf = client.get(
        "/api/policy",
        headers={"X-ArtifactDiff-Session": SESSION_TOKEN, "X-ArtifactDiff-CSRF": "d" * 43},
    )

    assert [
        (response.status_code, response.text)
        for response in (
            missing_session,
            missing_csrf,
            invalid_session,
            invalid_csrf,
        )
    ] == [(403, "forbidden")] * 4


def test_session_exchange_concurrently_consumes_the_fragment_token_once(tmp_path: Path) -> None:
    """A check-then-set race could grant two callers the same one-time capability."""
    app = create_review_app(
        ReviewContext(
            application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
        ),
        SESSION_TOKEN,
        CSRF_TOKEN,
    )
    app.state.bound_host = "127.0.0.1:8765"
    barrier = threading.Barrier(2)
    results: list[int] = []

    def exchange_once() -> None:
        with AsgiClient(app, base_url="http://127.0.0.1:8765") as concurrent_client:
            barrier.wait()
            results.append(
                concurrent_client.post(
                    "/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN}
                ).status_code
            )

    workers = [threading.Thread(target=exchange_once) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert sorted(results) == [200, 403]


def test_mutating_routes_require_exact_origin_and_json_content_type(client: AsgiClient) -> None:
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


def test_shutdown_is_one_use_and_server_shutdown_is_idempotent(client: AsgiClient) -> None:
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


def test_idle_server_stops_and_releases_its_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unopened review URL must not leave a loopback listener running forever."""
    monkeypatch.setattr("artifactdiff.review_web.server._IDLE_TIMEOUT_SECONDS", 0.05)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    address = server.socket.getsockname()

    server.thread.join(timeout=2.0)

    assert not server.thread.is_alive()
    with pytest.raises(OSError):
        server.socket.getsockname()
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=0.2)


def test_accepted_loopback_activity_resets_the_idle_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An activity callback omitted from the accepted request path expires active review sessions."""
    monkeypatch.setattr("artifactdiff.review_web.server._IDLE_TIMEOUT_SECONDS", 0.15)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    base_url = server.url.split("/#", maxsplit=1)[0]
    try:
        time.sleep(0.08)
        assert httpx.get(base_url, timeout=1.0).status_code == 200
        time.sleep(0.08)
        assert server.thread.is_alive()
        server.thread.join(timeout=1.0)
        assert not server.thread.is_alive()
    finally:
        server.shutdown()


def test_shutdown_timeout_can_be_retried_until_cleanup_completes() -> None:
    """Marking a timed-out shutdown closed would leave its socket permanently owned."""
    release = threading.Event()
    thread = threading.Thread(target=release.wait)
    thread.start()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    class Server:
        should_exit = False

    review_server = ReviewServer("http://127.0.0.1/", listener, thread, Server())  # type: ignore[arg-type]
    try:
        with pytest.raises(RuntimeError):
            review_server.shutdown(timeout_seconds=0.01)
        release.set()
        review_server.shutdown(timeout_seconds=1.0)
        review_server.shutdown(timeout_seconds=0.01)
    finally:
        release.set()
        thread.join(timeout=1.0)

    assert review_server.closed
    with pytest.raises(OSError):
        listener.getsockname()


def test_windows_listener_uses_exclusive_address_ownership(tmp_path: Path) -> None:
    """SO_REUSEADDR on Windows lets another process steal a local review port."""
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            assert server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE) == 1
    finally:
        server.shutdown()


def test_live_valid_wrong_host_rejection_has_security_headers_but_parser_errors_are_outside_asgi(
    tmp_path: Path,
) -> None:
    """Only a syntactically valid wrong Host reaches the ASGI security middleware."""
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    host, port = server.socket.getsockname()
    requests = {
        "wrong": f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n",
        "duplicate": (
            f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nHost: localhost:{port}\r\n"
            "Connection: close\r\n\r\n"
        ),
        "missing": "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
        "malformed": f"GET / HTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
    }
    try:
        responses = {
            label: _raw_response(host, port, request) for label, request in requests.items()
        }
    finally:
        server.shutdown()

    assert responses["wrong"].startswith("HTTP/1.1 400")
    assert "content-security-policy:" in responses["wrong"].lower()
    for label in ("duplicate", "missing", "malformed"):
        assert responses[label].startswith("HTTP/1.1 400")
        assert "content-security-policy:" not in responses[label].lower()


def _raw_response(host: str, port: int, request: str) -> str:
    with socket.create_connection((host, port), timeout=2.0) as connection:
        connection.sendall(request.encode("ascii"))
        chunks: list[bytes] = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks).decode("latin1")
