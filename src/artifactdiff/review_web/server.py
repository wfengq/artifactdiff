"""Lifecycle management for the review desk's one loopback listener."""

from __future__ import annotations

import secrets
import socket
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass

import uvicorn

from artifactdiff.review_web.app import ReviewContext, create_review_app

_START_TIMEOUT_SECONDS = 5.0


@dataclass(slots=True)
class ReviewServer:
    """A started in-process Uvicorn server bound to exactly one IPv4 socket."""

    url: str
    socket: socket.socket
    thread: threading.Thread
    _uvicorn: uvicorn.Server
    _closed: bool = False

    def shutdown(self) -> None:
        """Stop the listener once; repeat calls are safe and leave no child process."""
        if self._closed:
            return
        self._closed = True
        self._uvicorn.should_exit = True
        self.thread.join(timeout=_START_TIMEOUT_SECONDS)
        if self.thread.is_alive():
            raise RuntimeError("review server did not stop")
        self.socket.close()


def serve_review(context: ReviewContext, *, open_browser: bool = True) -> ReviewServer:
    """Start the local review desk and return its fragment-token launch URL."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(socket.SOMAXCONN)
    listener.setblocking(False)
    host, port = listener.getsockname()
    session_token = _new_token()
    app = create_review_app(context, session_token=session_token, csrf_token=_new_token())
    app.state.bound_host = f"{host}:{port}"
    config = uvicorn.Config(app, access_log=False, host="127.0.0.1", log_level="warning")
    uvicorn_server = uvicorn.Server(config)
    thread = threading.Thread(
        target=uvicorn_server.run,
        kwargs={"sockets": [listener]},
        name="artifactdiff-review-loopback",
        daemon=False,
    )
    review_server = ReviewServer(
        url=f"http://{host}:{port}/#token={session_token}",
        socket=listener,
        thread=thread,
        _uvicorn=uvicorn_server,
    )
    # A request handler runs on this very thread, so it may only request the
    # Uvicorn loop to exit. The owner joins and closes the listener afterwards.
    app.state.shutdown_callback = _request_shutdown(uvicorn_server)
    thread.start()
    _wait_until_started(uvicorn_server, review_server)
    print(review_server.url, flush=True)
    if open_browser:
        webbrowser.open(review_server.url)
    return review_server


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _wait_until_started(server: uvicorn.Server, review_server: ReviewServer) -> None:
    deadline = time.monotonic() + _START_TIMEOUT_SECONDS
    while not server.started:
        if not review_server.thread.is_alive():
            review_server.socket.close()
            raise RuntimeError("review server failed to start")
        if time.monotonic() >= deadline:
            review_server.shutdown()
            raise RuntimeError("review server did not start")
        time.sleep(0.01)


def _request_shutdown(server: uvicorn.Server) -> Callable[[], None]:
    def request_shutdown() -> None:
        server.should_exit = True

    return request_shutdown
