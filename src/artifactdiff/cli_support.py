"""Shared command-line adapter helpers; no domain behavior lives here."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import cast

import typer

from artifactdiff.errors import ArtifactDiffError, SignatureError
from artifactdiff.trust import LocalEd25519SigningProvider, TrustStore


def exit_for_error(error: ArtifactDiffError) -> None:
    typer.echo(f"ArtifactDiff error: {error}", err=True)
    raise typer.Exit(2)


def trust_store_from(path: Path | None) -> TrustStore:
    if path is None:
        return TrustStore(identities=[])
    try:
        return TrustStore.model_validate_json(path.read_bytes())
    except (OSError, TypeError, ValueError):
        raise SignatureError("invalid trust store") from None


class _PromptSecret:
    def get_secret(self, identity: str) -> bytes:
        if not sys.stdin.isatty():
            raise SignatureError("private-key passphrase requires an interactive terminal")
        passphrase = cast(
            str, typer.prompt(f"Passphrase for {identity}", hide_input=True, err=True)
        )
        return passphrase.encode("utf-8")


def interactive_signer(
    identity: str, key: Path, trust_store: TrustStore
) -> LocalEd25519SigningProvider:
    return LocalEd25519SigningProvider(identity, key, _PromptSecret(), trust_store)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
