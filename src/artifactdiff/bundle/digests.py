"""Canonical serialization and digest helpers for Review Bundles."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import TypeAlias

from pydantic import BaseModel
from pydantic_core import PydanticSerializationError

from artifactdiff.errors import BundleError

CanonicalValue: TypeAlias = (
    None | bool | int | float | str | list["CanonicalValue"] | dict[str, "CanonicalValue"]
)


def _sort_key(value: CanonicalValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalize(value: object) -> CanonicalValue:
    if isinstance(value, Path):
        return unicodedata.normalize("NFC", value.as_posix())
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BundleError("bundle object cannot be canonicalized")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, CanonicalValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise BundleError("bundle object cannot be canonicalized")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise BundleError("bundle object cannot be canonicalized")
            normalized[normalized_key] = _normalize(item)
        return dict(sorted(normalized.items()))
    if isinstance(value, (set, frozenset)):
        return sorted((_normalize(item) for item in value), key=_sort_key)
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise BundleError("bundle object cannot be canonicalized")


def canonical_bytes(value: BaseModel | dict[str, object]) -> bytes:
    try:
        payload = (
            value.model_dump(mode="python", warnings="error")
            if isinstance(value, BaseModel)
            else value
        )
        normalized = _normalize(payload)
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        PydanticSerializationError,
        RecursionError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        raise BundleError("bundle object cannot be canonicalized") from None


def canonical_digest(value: BaseModel | dict[str, object]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def canonical_file_digest(path: Path) -> str:
    """Return the SHA-256 digest of the exact file bytes."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise BundleError("unable to digest bundle payload") from None
    return digest.hexdigest()
