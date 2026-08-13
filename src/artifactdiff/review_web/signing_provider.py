"""Server-side signing operations for the local review desk.

Python cannot guarantee erasure of immutable strings or runtime-managed copies. The
reference provider therefore limits passphrase/key lifetime and overwrites its mutable
buffer, while high-assurance deployments should prefer an OS keychain or HSM provider.
"""

from __future__ import annotations

import getpass
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.policy import FrozenPolicy
from artifactdiff.review import ApprovalEvent
from artifactdiff.session import authorize_policy
from artifactdiff.trust import (
    LocalEd25519SigningProvider,
    PolicyAuthorization,
    SigningProvider,
    TrustStore,
)


class ReviewSigningProvider(Protocol):
    """High-level operations available to an authenticated review session."""

    def sign_policy(self, frozen: FrozenPolicy) -> PolicyAuthorization: ...

    def sign_approval(self, bundle: Path, finding_id: str, reason: str) -> ApprovalEvent: ...


@dataclass(slots=True)
class _ScopedSecret:
    buffer: bytearray

    def get_secret(self, identity: str) -> bytes:
        del identity
        return bytes(self.buffer)

    def erase(self) -> None:
        for index in range(len(self.buffer)):
            self.buffer[index] = 0


@dataclass(frozen=True, slots=True)
class InteractiveEd25519SigningProvider:
    """Prompt on the server and keep secrets outside browser/API payloads."""

    application: ArtifactDiffApplication
    identity: str
    private_key_path: Path
    trust_store: TrustStore

    def sign_policy(self, frozen: FrozenPolicy) -> PolicyAuthorization:
        secret, signer = self._prompted_signer()
        try:
            return authorize_policy(frozen, signer=signer)
        finally:
            secret.erase()

    def sign_approval(self, bundle: Path, finding_id: str, reason: str) -> ApprovalEvent:
        secret, signer = self._prompted_signer()
        try:
            return self.application.approve(bundle, finding_id, reason, signer=signer)
        finally:
            secret.erase()

    def _prompted_signer(self) -> tuple[_ScopedSecret, LocalEd25519SigningProvider]:
        passphrase = getpass.getpass(f"Passphrase for {self.identity}: ")
        secret = _ScopedSecret(bytearray(passphrase, "utf-8"))
        del passphrase
        return secret, LocalEd25519SigningProvider(
            self.identity,
            self.private_key_path,
            secret,
            self.trust_store,
        )


@dataclass(slots=True)
class FakeSigningProvider:
    """Deterministic high-level provider used by integration tests."""

    application: ArtifactDiffApplication
    signer: SigningProvider
    policy_calls: list[str] = field(default_factory=list)
    approval_calls: list[tuple[Path, str]] = field(default_factory=list)

    def sign_policy(self, frozen: FrozenPolicy) -> PolicyAuthorization:
        self.policy_calls.append(frozen.canonical_sha256)
        return authorize_policy(frozen, signer=self.signer)

    def sign_approval(self, bundle: Path, finding_id: str, reason: str) -> ApprovalEvent:
        self.approval_calls.append((bundle, finding_id))
        return self.application.approve(bundle, finding_id, reason, signer=self.signer)
