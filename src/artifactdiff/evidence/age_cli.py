"""Argument-safe first-party age CLI adapter."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from artifactdiff.errors import EncryptionUnavailableError, EvidenceError

_RECIPIENT = re.compile(r"(?:age1|age-plugin-)[A-Za-z0-9._+-]{6,200}")


@dataclass(frozen=True, slots=True)
class AgeCliProvider:
    executable: Path

    def encrypt(self, source: Path, output: Path, recipients: Sequence[str]) -> Path:
        checked = list(recipients)
        if not checked or any(_RECIPIENT.fullmatch(item) is None for item in checked):
            raise EvidenceError("sealed archives require valid age recipients")
        if source.is_symlink() or not source.is_file() or output.is_symlink() or output.exists():
            raise EvidenceError("invalid age encryption path")
        arguments = [str(self.executable)]
        for recipient in checked:
            arguments.extend(["-r", recipient])
        arguments.extend(["-o", str(output), str(source)])
        return self._run(arguments, output, action="encryption")

    def decrypt(
        self,
        source: Path,
        output: Path,
        *,
        identities: Sequence[Path] = (),
    ) -> Path:
        """Decrypt an age archive without exposing key material to a command shell."""
        if source.is_symlink() or not source.is_file() or output.is_symlink() or output.exists():
            raise EvidenceError("invalid age decryption path")
        checked_identities: list[Path] = []
        for identity in identities:
            if identity.is_symlink() or not identity.is_file():
                raise EvidenceError("invalid age identity path")
            checked_identities.append(identity)
        arguments = [str(self.executable), "-d"]
        for identity in checked_identities:
            arguments.extend(["-i", str(identity)])
        arguments.extend(["-o", str(output), str(source)])
        return self._run(arguments, output, action="decryption")

    @staticmethod
    def _run(arguments: list[str], output: Path, *, action: str) -> Path:
        try:
            result = subprocess.run(
                arguments,
                shell=False,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError:
            output.unlink(missing_ok=True)
            raise EncryptionUnavailableError(
                "Install age and ensure the 'age' executable is on PATH."
            ) from None
        except subprocess.TimeoutExpired:
            output.unlink(missing_ok=True)
            raise EvidenceError(f"age {action} timed out") from None
        except OSError:
            output.unlink(missing_ok=True)
            raise EvidenceError(f"age {action} failed") from None
        if result.returncode != 0 or output.is_symlink() or not output.is_file():
            output.unlink(missing_ok=True)
            raise EvidenceError(f"age {action} failed")
        return output
