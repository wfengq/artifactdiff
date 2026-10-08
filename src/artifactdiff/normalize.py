"""Deterministic text and file normalization helpers."""

import hashlib
import re
import unicodedata
from pathlib import Path


def normalize_text(text: str) -> str:
    """Normalize text for stable semantic comparisons."""
    normalized = unicodedata.normalize("NFKC", text).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", normalized).strip().casefold()


def comparison_text(text: str) -> str:
    """Normalize only what never carries meaning: Unicode composition and whitespace.

    Unlike ``normalize_text`` this keeps case and compatibility characters, so a
    defined term ("Affiliate" -> "affiliate") or a full-width character is a change.
    """
    normalized = unicodedata.normalize("NFC", text).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", normalized).strip()


def comparison_fingerprint(text: str) -> str:
    """Return the SHA-256 of ``comparison_text``: case-sensitive, whitespace-insensitive."""
    return hashlib.sha256(comparison_text(text).encode("utf-8")).hexdigest()


def fingerprint(text: str) -> str:
    """Return the SHA-256 fingerprint of normalized text."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    """Return the SHA-256 fingerprint of a file's raw bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
