from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import httpx
import pytest

import artifactdiff.review_web.server as review_server_module
from artifactdiff.errors import ArtifactDiffError, ReviewServerError
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


def test_only_successful_shell_session_and_authenticated_api_actions_record_activity(
    tmp_path: Path,
) -> None:
    """Recording rejected requests lets unauthenticated traffic prolong the server lifetime."""
    app = create_review_app(
        ReviewContext(
            application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
        ),
        SESSION_TOKEN,
        CSRF_TOKEN,
    )
    app.state.bound_host = "127.0.0.1:8765"
    activity: list[str] = []
    app.state.activity_callback = lambda: activity.append("accepted")
    client = AsgiClient(app, base_url="http://127.0.0.1:8765")

    assert client.get("/").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/nope.js").status_code == 404
    assert client.get("/api/policy").status_code == 403
    assert (
        client.post("/api/session", headers={"X-ArtifactDiff-Session": SESSION_TOKEN}).status_code
        == 200
    )
    assert client.get("/api/policy", headers=session_headers()).status_code == 501

    assert activity == ["accepted", "accepted", "accepted", "accepted"]


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


def test_bind_failure_closes_listener_and_raises_public_domain_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A handled bind failure must neither leak a listener nor expose its OS diagnostic."""
    secret = "private bind diagnostic"

    class Listener:
        family = socket.AF_INET
        closed = False

        def setsockopt(self, *_args: object) -> None:
            return None

        def bind(self, _address: object) -> None:
            raise OSError(secret)

        def close(self) -> None:
            self.closed = True

    listener = Listener()
    monkeypatch.setattr(review_server_module.socket, "socket", lambda *_args: listener)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )

    with pytest.raises(ArtifactDiffError, match="local review server operation failed") as caught:
        serve_review(context, open_browser=False)

    assert listener.closed
    assert secret not in str(caught.value)


def test_browser_start_failure_stops_server_and_closes_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed browser launch must unwind the already-started loopback lifecycle."""
    created: list[ReviewServer] = []
    secret = "private browser diagnostic"

    def capture_server(*args: object, **kwargs: object) -> ReviewServer:
        server = ReviewServer(*args, **kwargs)  # type: ignore[arg-type]
        created.append(server)
        return server

    def fail_browser(_url: str) -> bool:
        raise review_server_module.webbrowser.Error(secret)

    monkeypatch.setattr(review_server_module, "ReviewServer", capture_server)
    monkeypatch.setattr(review_server_module.webbrowser, "open", fail_browser)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )

    try:
        with pytest.raises(
            ArtifactDiffError, match="local review server operation failed"
        ) as caught:
            serve_review(context, open_browser=True)
        assert len(created) == 1
        assert created[0].closed
        assert not created[0].thread.is_alive()
        assert secret not in str(caught.value)
        assert "token=" not in capsys.readouterr().out
    finally:
        if created:
            created[0].shutdown()


def test_browser_refusal_stops_server_without_printing_launch_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A browser controller returning false is a startup failure, not a live desk."""
    created: list[ReviewServer] = []

    def capture_server(*args: object, **kwargs: object) -> ReviewServer:
        server = ReviewServer(*args, **kwargs)  # type: ignore[arg-type]
        created.append(server)
        return server

    monkeypatch.setattr(review_server_module, "ReviewServer", capture_server)
    monkeypatch.setattr(review_server_module.webbrowser, "open", lambda _url: False)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )

    try:
        with pytest.raises(ArtifactDiffError, match="local review server operation failed"):
            serve_review(context, open_browser=True)
        assert len(created) == 1
        assert created[0].closed
        assert not created[0].thread.is_alive()
        assert "token=" not in capsys.readouterr().out
    finally:
        if created:
            created[0].shutdown()


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


def test_early_idle_callback_keeps_the_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timer callback before its deadline must not leave the listener running."""
    monkeypatch.setattr("artifactdiff.review_web.server._IDLE_TIMEOUT_SECONDS", 0.5)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    try:
        assert server._idle_timer is not None
        assert server._idle_deadline is not None
        server._idle_timer.cancel()
        assert time.monotonic() < server._idle_deadline
        server._idle_expired(server._watchdog_generation, server._idle_deadline)

        server.thread.join(timeout=2.0)
        assert not server.thread.is_alive()
    finally:
        server.shutdown()


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


def test_shutdown_releases_lifecycle_state_before_waiting_for_the_server_thread() -> None:
    """Joining while holding lifecycle state deadlocks a request completing accepted activity."""
    listener = _listener()

    class Server:
        should_exit = False

    class Thread:
        def __init__(self) -> None:
            self.server: ReviewServer | None = None
            self.activity_finished = threading.Event()

        def join(self, timeout: float) -> None:
            assert self.server is not None
            activity = threading.Thread(
                target=lambda: (self.server.reset_idle_timer(), self.activity_finished.set())
            )
            activity.start()
            activity.join(timeout)

        def is_alive(self) -> bool:
            return not self.activity_finished.is_set()

    thread = Thread()
    review_server = ReviewServer("http://127.0.0.1/", listener, thread, Server())  # type: ignore[arg-type]
    thread.server = review_server

    review_server.shutdown(timeout_seconds=0.1)

    assert review_server.closed


def test_stale_watchdog_callback_cannot_shutdown_after_newer_accepted_activity() -> None:
    """Timer cancellation alone cannot stop a callback that is already runnable."""
    listener = _listener()

    class Server:
        should_exit = False

    thread = threading.Thread(target=lambda: None)
    thread.start()
    thread.join()
    review_server = ReviewServer("http://127.0.0.1/", listener, thread, Server())  # type: ignore[arg-type]
    review_server.reset_idle_timer()
    stale_generation = review_server._watchdog_generation
    stale_deadline = review_server._idle_deadline
    review_server.reset_idle_timer()

    assert stale_deadline is not None
    review_server._idle_expired(stale_generation, stale_deadline)

    assert not review_server.shutdown_requested
    assert not Server.should_exit
    review_server.shutdown()


def test_activity_after_shutdown_request_cannot_install_a_new_watchdog() -> None:
    """A terminal shutdown request must not be undone by a racing accepted request."""
    listener = _listener()

    class Server:
        should_exit = False

    thread = threading.Thread(target=lambda: None)
    thread.start()
    thread.join()
    review_server = ReviewServer("http://127.0.0.1/", listener, thread, Server())  # type: ignore[arg-type]
    review_server.request_shutdown()
    review_server.reset_idle_timer()

    assert review_server.shutdown_requested
    assert review_server._idle_timer is None
    assert review_server._uvicorn.should_exit
    review_server.shutdown()


def test_invalid_traffic_does_not_extend_idle_lifetime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counting failed token checks or 404s as activity lets an attacker keep the desk alive."""
    monkeypatch.setattr(review_server_module, "_IDLE_TIMEOUT_SECONDS", 0.12)
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )
    server = serve_review(context, open_browser=False)
    base_url = server.url.split("/#", maxsplit=1)[0]
    try:
        deadline = time.monotonic() + 0.35
        while time.monotonic() < deadline and server.thread.is_alive():
            try:
                assert httpx.get(base_url + "/missing", timeout=1.0).status_code == 404
                assert httpx.get(base_url + "/api/policy", timeout=1.0).status_code == 403
            except httpx.TransportError:
                break
            time.sleep(0.02)
        server.thread.join(timeout=1.0)
        assert not server.thread.is_alive()
    finally:
        server.shutdown()


def test_simultaneous_shutdown_callers_close_the_listener_once() -> None:
    """Competing finalizers must not double-close the listener or leave it open."""
    close_count = 0
    close_lock = threading.Lock()

    class Listener:
        def close(self) -> None:
            nonlocal close_count
            with close_lock:
                close_count += 1

    class Server:
        should_exit = False

    thread = threading.Thread(target=lambda: None)
    thread.start()
    thread.join()
    review_server = ReviewServer("http://127.0.0.1/", Listener(), thread, Server())  # type: ignore[arg-type]
    callers = [threading.Thread(target=review_server.shutdown) for _ in range(2)]
    for caller in callers:
        caller.start()
    for caller in callers:
        caller.join()

    assert review_server.closed
    assert close_count == 1


def test_uvicorn_worker_failure_never_reaches_threading_excepthook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A worker failure must become one generic owner-thread error, never a traceback."""
    secret = "SECRET UVICORN FAILURE"
    unhandled: list[BaseException] = []

    def fail_run(*args: object, **kwargs: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(review_server_module.uvicorn.Server, "run", fail_run)
    monkeypatch.setattr(
        threading,
        "excepthook",
        lambda arguments: unhandled.append(arguments.exc_value),
    )
    context = ReviewContext(
        application=object(), mode="bundle", target_path=tmp_path, signing_provider=None
    )

    with pytest.raises(ReviewServerError, match="local review server operation failed"):
        serve_review(context, open_browser=False)

    captured = capsys.readouterr()
    assert unhandled == []
    assert secret not in captured.err
    assert "Traceback" not in captured.err


def test_worker_finalizer_close_failure_is_sanitized_and_owner_cleanup_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A close error in the worker must not escape its thread or prevent owner cleanup."""
    secret = "SECRET LISTENER CLOSE FAILURE"
    unhandled: list[BaseException] = []

    class Listener:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError(secret)

    class Server:
        should_exit = False

    holder: list[ReviewServer] = []
    thread = threading.Thread(target=lambda: holder[0].finalize_after_server_exit())
    listener = Listener()
    review_server = ReviewServer(
        "http://127.0.0.1/",
        listener,
        thread,
        Server(),  # type: ignore[arg-type]
    )
    holder.append(review_server)
    monkeypatch.setattr(
        threading,
        "excepthook",
        lambda arguments: unhandled.append(arguments.exc_value),
    )

    thread.start()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert unhandled == []
    with pytest.raises(ReviewServerError, match="local review server operation failed"):
        review_server.shutdown()
    assert review_server.closed
    assert listener.close_calls == 2


def test_shutdown_surfaces_worker_failure_recorded_during_join() -> None:
    """A worker that closes during join must not make its pending failure disappear."""

    class Listener:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    class Server:
        should_exit = False

    class Thread:
        server: ReviewServer | None = None

        def join(self, timeout: float) -> None:
            assert self.server is not None
            self.server.record_worker_failure()
            self.server.finalize_after_server_exit()

        def is_alive(self) -> bool:
            return False

    listener = Listener()
    thread = Thread()
    review_server = ReviewServer(
        "http://127.0.0.1/",
        listener,
        thread,  # type: ignore[arg-type]
        Server(),  # type: ignore[arg-type]
    )
    thread.server = review_server

    with pytest.raises(ReviewServerError, match="local review server operation failed"):
        review_server.shutdown()

    assert review_server.closed
    assert listener.close_calls == 1


def _raw_response(host: str, port: int, request: str) -> str:
    with socket.create_connection((host, port), timeout=2.0) as connection:
        connection.sendall(request.encode("ascii"))
        chunks: list[bytes] = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks).decode("latin1")


def _listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    return listener
