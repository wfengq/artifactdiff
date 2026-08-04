"""Deterministic canonical serialization for contract policies."""

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import TypeAlias

from artifactdiff.errors import PolicyValidationError
from artifactdiff.policy.models import ContractPolicy

CanonicalValue: TypeAlias = (
    None | bool | int | float | str | list["CanonicalValue"] | dict[str, "CanonicalValue"]
)


def _normalized_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _sort_key(value: CanonicalValue) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalize(value: object) -> CanonicalValue:
    if isinstance(value, Path):
        return _normalized_string(value.as_posix())
    if isinstance(value, str):
        return _normalized_string(value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PolicyValidationError("policy cannot be canonicalized")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, CanonicalValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyValidationError("policy cannot be canonicalized")
            normalized_key = _normalized_string(key)
            if normalized_key in normalized:
                raise PolicyValidationError("policy cannot be canonicalized")
            normalized[normalized_key] = _normalize(item)
        return dict(sorted(normalized.items()))
    if isinstance(value, (set, frozenset)):
        normalized_items = [_normalize(item) for item in value]
        return sorted(normalized_items, key=_sort_key)
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise PolicyValidationError("policy cannot be canonicalized")


def _canonical_payload(policy: ContractPolicy) -> dict[str, CanonicalValue]:
    normalized = _normalize(policy.model_dump(mode="python"))
    if not isinstance(normalized, dict):
        raise PolicyValidationError("policy cannot be canonicalized")
    return normalized


def canonical_policy_bytes(policy: ContractPolicy) -> bytes:
    """Return compact NFC-normalized canonical JSON bytes for a policy."""
    payload = _canonical_payload(policy)
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def policy_digest(policy: ContractPolicy) -> str:
    """Return the lowercase SHA-256 digest of canonical policy bytes."""
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()
