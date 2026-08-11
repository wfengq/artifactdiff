"""Shared canonical event digest helpers."""

from __future__ import annotations

from pydantic import BaseModel

from artifactdiff.bundle.digests import canonical_digest


def unsigned_approval_digest(event: BaseModel) -> str:
    payload = event.model_dump(mode="json", exclude={"signature"}, warnings="error")
    return canonical_digest(dict(payload))


def signed_event_digest(event: BaseModel) -> str:
    return canonical_digest(event)
