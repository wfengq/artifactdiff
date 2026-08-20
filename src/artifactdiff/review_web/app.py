"""The deliberately data-free HTTP shell for the local review desk."""

from __future__ import annotations

import hmac
import json
import re
import threading
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.errors import ArtifactDiffError
from artifactdiff.review_web.signing_provider import ReviewSigningProvider
from artifactdiff.review_web.views import ReviewViews, public_view_error

_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
_SESSION_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SECURITY_HEADERS = (
    (b"content-security-policy", _CSP.encode("ascii")),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
    (b"cross-origin-resource-policy", b"same-origin"),
)
_SECURITY_HEADER_NAMES = {name for name, _ in _SECURITY_HEADERS}
_FORWARDED_HEADERS = {b"forwarded", b"x-forwarded-for", b"x-forwarded-host", b"x-forwarded-proto"}
_MUTATING_PATHS = {
    "/api/policy",
    "/api/policy/seal",
    "/api/approvals",
    "/api/shutdown",
}
_MAX_JSON_BODY_BYTES = 64 * 1024


class _BodyTooLarge(ValueError):
    pass


async def _bounded_json(request: Request) -> object:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError:
            raise ValueError("invalid content length") from None
        if declared_size > _MAX_JSON_BODY_BYTES:
            raise _BodyTooLarge
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_JSON_BODY_BYTES:
            raise _BodyTooLarge
    return json.loads(bytes(body))


@dataclass(frozen=True, slots=True)
class ReviewContext:
    """Server-owned dependencies for one local review task.

    The shell deliberately does not read any of these values. Task 4 supplies
    authenticated views that consume the facade and the signing provider.
    """

    application: ArtifactDiffApplication
    mode: str
    target_path: Path
    signing_provider: ReviewSigningProvider | None
    output_path: Path | None = None
    force_output: bool = False


@dataclass(slots=True)
class _SessionState:
    session_token: str
    csrf_token: str
    exchanged: bool = False
    shutdown_used: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class _LoopbackSecurityMiddleware:
    """Apply response headers and fail closed unless the exact listener is addressed."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw_headers = message.setdefault("headers", [])
                raw_headers[:] = [
                    (name, value)
                    for name, value in raw_headers
                    if name.lower() not in _SECURITY_HEADER_NAMES
                ]
                raw_headers.extend(_SECURITY_HEADERS)
            await send(message)

        if not _is_exact_loopback_request(scope):
            await PlainTextResponse("invalid host", status_code=400)(scope, receive, secure_send)
            return
        await self.app(scope, receive, secure_send)


def _is_exact_loopback_request(scope: Scope) -> bool:
    expected_host = scope["app"].state.bound_host
    if not isinstance(expected_host, str):
        return False
    raw_headers = scope.get("headers", [])
    hosts = [value for name, value in raw_headers if name.lower() == b"host"]
    if len(hosts) != 1 or hosts[0] != expected_host.encode("ascii"):
        return False
    return not any(
        name.lower() in _FORWARDED_HEADERS or name.lower().startswith(b"x-forwarded-")
        for name, _ in raw_headers
    )


def create_review_app(context: ReviewContext, session_token: str, csrf_token: str) -> Starlette:
    """Create a fail-closed local shell with no domain data routes.

    ``bound_host`` remains unset until :func:`serve_review` binds the IPv4
    socket, so an app constructed outside that lifecycle refuses all requests.
    """
    if _SESSION_TOKEN_PATTERN.fullmatch(session_token) is None:
        raise ValueError("review session token must be a 43-character base64url token")
    state = _SessionState(session_token=session_token, csrf_token=csrf_token)
    views = ReviewViews(
        context.application,
        context.mode,
        context.target_path,
        context.signing_provider,
        context.output_path,
        context.force_output,
    )

    async def shell(_: Request) -> Response:
        response = _asset_response("index.html", "text/html; charset=utf-8")
        _record_activity(_.app)
        return response

    async def asset(request: Request) -> Response:
        name = request.path_params["name"]
        media_type = {"app.js": "application/javascript", "styles.css": "text/css"}.get(name)
        if media_type is None:
            return PlainTextResponse("not found", status_code=404)
        response = _asset_response(name, media_type)
        _record_activity(request.app)
        return response

    async def establish_session(request: Request) -> Response:
        with state.lock:
            if (
                state.exchanged
                or request.query_params
                or not _matches(request.headers.get("x-artifactdiff-session"), state.session_token)
            ):
                return PlainTextResponse("forbidden", status_code=403)
            state.exchanged = True
        _record_activity(request.app)
        return JSONResponse({"csrf_token": state.csrf_token})

    async def protected(request: Request) -> Response:
        if not _authenticated(request, state):
            return PlainTextResponse("forbidden", status_code=403)
        if request.method == "POST" and request.url.path in _MUTATING_PATHS:
            rejected = _reject_mutation(request)
            if rejected is not None:
                return rejected
        _record_activity(request.app)
        if request.url.path == "/api/shutdown":
            if state.shutdown_used:
                return PlainTextResponse("forbidden", status_code=403)
            state.shutdown_used = True
            callback = request.app.state.shutdown_callback
            if callable(callback):
                callback()
            return JSONResponse({"status": "shutting_down"})
        if not isinstance(context.application, ArtifactDiffApplication):
            return JSONResponse({"detail": "review view is not installed"}, status_code=501)
        try:
            path = request.url.path
            if path == "/api/policy" and request.method == "GET":
                payload = views.policy_overview()
            elif path == "/api/policy":
                payload = views.draft_policy(await _bounded_json(request))
            elif path == "/api/policy/seal":
                payload = views.seal_policy(await _bounded_json(request))
            elif path == "/api/bundle":
                payload = views.bundle_overview(
                    int(request.query_params.get("event_cursor", "0")),
                    int(request.query_params.get("event_limit", "100")),
                )
            elif path == "/api/findings":
                payload = views.list_findings(
                    int(request.query_params.get("cursor", "0")),
                    int(request.query_params.get("limit", "20")),
                )
            elif path.startswith("/api/findings/"):
                payload = views.finding(request.path_params["id"])
            elif path == "/api/approvals":
                payload = views.approve(await _bounded_json(request))
            else:
                return JSONResponse({"error": "not found"}, status_code=404)
        except _BodyTooLarge:
            return JSONResponse({"error": "review request is too large"}, status_code=413)
        except (ArtifactDiffError, ValidationError, ValueError, json.JSONDecodeError) as error:
            status, message = public_view_error(error)
            return JSONResponse({"error": message}, status_code=status)
        return JSONResponse(payload)

    app = Starlette(
        debug=False,
        routes=[
            Route("/", shell, methods=["GET"]),
            Route("/assets/{name}", asset, methods=["GET"]),
            Route("/api/session", establish_session, methods=["POST"]),
            Route("/api/policy", protected, methods=["GET", "POST"]),
            Route("/api/policy/seal", protected, methods=["POST"]),
            Route("/api/bundle", protected, methods=["GET"]),
            Route("/api/findings", protected, methods=["GET"]),
            Route("/api/findings/{id}", protected, methods=["GET"]),
            Route("/api/approvals", protected, methods=["POST"]),
            Route("/api/shutdown", protected, methods=["POST"]),
        ],
    )
    app.state.bound_host = None
    app.state.shutdown_callback = None
    app.state.activity_callback = None
    # Starlette's server-error middleware otherwise sits outside user
    # middleware. Wrap the completed stack so even an unexpected 500 carries
    # the same fail-closed response headers.
    app.middleware_stack = _LoopbackSecurityMiddleware(app.build_middleware_stack())
    return app


def _asset_response(name: str, media_type: str) -> Response:
    content = files("artifactdiff.review_web").joinpath("assets", name).read_text(encoding="utf-8")
    return Response(content, media_type=media_type)


def _record_activity(app: Starlette) -> None:
    callback = app.state.activity_callback
    if callable(callback):
        callback()


def _matches(actual: str | None, expected: str) -> bool:
    return actual is not None and hmac.compare_digest(actual, expected)


def _authenticated(request: Request, state: _SessionState) -> bool:
    return (
        state.exchanged
        and _matches(request.headers.get("x-artifactdiff-session"), state.session_token)
        and _matches(request.headers.get("x-artifactdiff-csrf"), state.csrf_token)
    )


def _reject_mutation(request: Request) -> Response | None:
    expected_origin = f"http://{request.app.state.bound_host}"
    if not _matches(request.headers.get("origin"), expected_origin):
        return PlainTextResponse("forbidden", status_code=403)
    if request.headers.get("content-type") != "application/json":
        return PlainTextResponse("unsupported media type", status_code=415)
    return None
