"""Small synchronous HTTP boundary for the ASGI review-shell tests."""

from __future__ import annotations

import asyncio
from typing import Any, Self

import httpx
from starlette.applications import Starlette


class AsgiClient:
    """Exercise the real ASGI app without Starlette's deprecated TestClient API."""

    def __init__(
        self, app: Starlette, *, base_url: str, raise_server_exceptions: bool = True
    ) -> None:
        self._app = app
        self._base_url = base_url
        self._raise_server_exceptions = raise_server_exceptions

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(
                app=self._app, raise_app_exceptions=self._raise_server_exceptions
            )
            async with httpx.AsyncClient(transport=transport, base_url=self._base_url) as client:
                return await client.request(method, url, **kwargs)

        return asyncio.run(send())
