"""Lifecycle management for the review desk's one loopback listener."""

from __future__ import annotations

import secrets
import socket
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from typing import Literal

import uvicorn

from artifactdiff.review_web.app import ReviewContext, create_review_app

_START_TIMEOUT_SECONDS = 5.0
_IDLE_TIMEOUT_SECONDS = 300.0


@dataclass(slots=True)
class ReviewServer:
    """A started in-process Uvicorn server bound to exactly one IPv4 socket."""

    url: str
    socket: socket.socket
    thread: threading.Thread
    _uvicorn: uvicorn.Server
    _idle_timeout_seconds: float = _IDLE_TIMEOUT_SECONDS
    _state: Literal["running", "shutdown_requested", "closed"] = "running"
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _finalizer_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _idle_timer: threading.Timer | None = field(default=None, repr=False)
    _watchdog_generation: int = 0
    _idle_deadline: float | None = None

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._state == "closed"

    @property
    def shutdown_requested(self) -> bool:
        with self._lock:
            return self._state != "running"

    def reset_idle_timer(self) -> None:
        """Keep the one owner-managed idle watchdog alive after valid loopback activity."""
        with self._lock:
            if self._state != "running":
                return
            self._watchdog_generation += 1
            generation = self._watchdog_generation
            deadline = time.monotonic() + self._idle_timeout_seconds
            self._idle_deadline = deadline
            if self._idle_timer is not None:
                self._idle_timer.cancel()
            self._idle_timer = threading.Timer(
                self._idle_timeout_seconds, self._idle_expired, args=(generation, deadline)
            )
            self._idle_timer.daemon = True
            self._idle_timer.start()

    def _idle_expired(self, generation: int, deadline: float) -> None:
        """Request exit only when this callback still owns the current deadline."""
        with self._lock:
            if (
                self._state != "running"
                or self._watchdog_generation != generation
                or self._idle_deadline != deadline
                or time.monotonic() < deadline
            ):
                return
            self._request_shutdown_locked()

    def request_shutdown(self) -> None:
        """Request shutdown from an ASGI handler without joining its own server thread."""
        with self._lock:
            self._request_shutdown_locked()

    def _request_shutdown_locked(self) -> None:
        if self._state != "running":
            return
        self._state = "shutdown_requested"
        self._uvicorn.should_exit = True
        self._watchdog_generation += 1
        self._idle_deadline = None
        if self._idle_timer is not None:
            self._idle_timer.cancel()
            self._idle_timer = None

    def shutdown(self, *, timeout_seconds: float = _START_TIMEOUT_SECONDS) -> None:
        """Stop and close once; a timeout remains retryable until cleanup completes."""
        with self._lock:
            if self._state == "closed":
                return
            self._request_shutdown_locked()
        self.thread.join(timeout=timeout_seconds)
        if self.thread.is_alive():
            raise RuntimeError("review server did not stop")
        with self._finalizer_lock:
            if self.closed:
                return
            self.socket.close()
            with self._lock:
                self._state = "closed"

    def finalize_after_server_exit(self) -> None:
        """Release the listener when an idle request stops Uvicorn without an owner call."""
        with self._finalizer_lock:
            with self._lock:
                if self._state == "closed":
                    return
                self._state = "shutdown_requested"
                self._watchdog_generation += 1
                self._idle_deadline = None
                if self._idle_timer is not None:
                    self._idle_timer.cancel()
                    self._idle_timer = None
            self.socket.close()
            with self._lock:
                self._state = "closed"


def serve_review(context: ReviewContext, *, open_browser: bool = True) -> ReviewServer:
    """Start the local review desk and return its fragment-token launch URL."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(socket.SOMAXCONN)
    listener.setblocking(False)
    host, port = listener.getsockname()
    session_token = _new_token()
    app = create_review_app(context, session_token=session_token, csrf_token=_new_token())
    app.state.bound_host = f"{host}:{port}"
    config = uvicorn.Config(
        app,
        access_log=False,
        host="127.0.0.1",
        log_level="warning",
        proxy_headers=False,
    )
    uvicorn_server = uvicorn.Server(config)
    holder: list[ReviewServer] = []

    def run_server() -> None:
        try:
            uvicorn_server.run(sockets=[listener])
        finally:
            holder[0].finalize_after_server_exit()

    thread = threading.Thread(target=run_server, name="artifactdiff-review-loopback", daemon=False)
    review_server = ReviewServer(
        url=f"http://{host}:{port}/#token={session_token}",
        socket=listener,
        thread=thread,
        _uvicorn=uvicorn_server,
        _idle_timeout_seconds=_IDLE_TIMEOUT_SECONDS,
    )
    holder.append(review_server)
    # A request handler runs on this very thread, so it may only request the
    # Uvicorn loop to exit. The owner joins and closes the listener afterwards.
    app.state.shutdown_callback = review_server.request_shutdown
    app.state.activity_callback = review_server.reset_idle_timer
    thread.start()
    _wait_until_started(uvicorn_server, review_server)
    review_server.reset_idle_timer()
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
