"""Source contracts: committed synthetic seeds and the CUAD v1 corpus."""

from __future__ import annotations

import hashlib
import random
import re
import shutil
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, cast

import yaml

from evaluation.models import AuthorizedEdit, Language, SourceContract

SYNTHETIC_DIR = Path(__file__).parent / "corpus" / "synthetic"

CUAD_URL = "https://zenodo.org/api/records/4595826/files/CUAD_v1.zip/content"
CUAD_SHA256 = "88b694d99007d39777fa44cd72daf8297773d285dc3eab0091ba32078888d18e"
CUAD_ATTRIBUTION = (
    "Contains material from the Contract Understanding Atticus Dataset (CUAD) v1 "
    "by The Atticus Project, licensed under CC BY 4.0."
)
CUAD_CONTRACT_COUNT = 510
_CUAD_TEXT_PREFIX = "CUAD_v1/full_contract_txt/"


class CuadChecksumError(Exception):
    """The CUAD archive does not match the pinned SHA-256."""


def load_synthetic(directory: Path = SYNTHETIC_DIR) -> list[SourceContract]:
    contracts = [_load_seed(path) for path in sorted(directory.glob("*.yaml"))]
    return sorted(contracts, key=lambda contract: contract.contract_id)


def _load_seed(path: Path) -> SourceContract:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: seed must be a mapping")
    language = data["language"]
    if language not in ("en", "zh"):
        raise ValueError(f"{path.name}: unsupported language {language!r}")
    paragraphs = tuple(str(item) for item in data["paragraphs"])
    edit = data["edit"]
    before = str(edit["before"])
    holders = [index for index, text in enumerate(paragraphs) if before in text]
    if len(holders) != 1 or paragraphs[holders[0]].count(before) != 1:
        raise ValueError(f"{path.name}: edit.before must occur in exactly one paragraph, once")
    return SourceContract(
        source="synthetic",
        contract_id=str(data["id"]),
        language=cast(Language, language),
        paragraphs=paragraphs,
        declared_edit=AuthorizedEdit(
            before=before,
            after=str(edit["after"]),
            paragraph_index=holders[0],
            clause_label=str(edit["clause_label"]),
            heading=str(edit["heading"]),
            anchor=str(edit["anchor"]),
        ),
    )


def fetch_cuad(
    data_dir: Path,
    *,
    archive: Path | None = None,
    opener: Callable[[str], BinaryIO] = urllib.request.urlopen,
) -> Path:
    """Download (or copy), verify and extract CUAD's plain-text contracts."""
    raw_dir = data_dir / "raw"
    generated_dir = data_dir / "generated"
    text_dir = generated_dir / "cuad"
    if text_dir.is_dir() and len(list(text_dir.glob("*.txt"))) == CUAD_CONTRACT_COUNT:
        return text_dir

    raw_dir.mkdir(parents=True, exist_ok=True)
    final_zip = raw_dir / "CUAD_v1.zip"
    if not final_zip.is_file() or _sha256(final_zip) != CUAD_SHA256:
        partial = raw_dir / "CUAD_v1.zip.part"
        try:
            if archive is not None:
                shutil.copyfile(archive, partial)
            else:
                with opener(CUAD_URL) as response, partial.open("wb") as handle:
                    shutil.copyfileobj(response, handle)
            digest = _sha256(partial)
            if digest != CUAD_SHA256:
                raise CuadChecksumError(
                    f"CUAD archive SHA-256 {digest} does not match pinned {CUAD_SHA256}"
                )
            partial.replace(final_zip)
        finally:
            partial.unlink(missing_ok=True)
            _remove_if_empty(raw_dir)
            _remove_if_empty(data_dir)

    generated_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="cuad-", dir=generated_dir))
    try:
        with zipfile.ZipFile(final_zip) as bundle:
            for info in bundle.infolist():
                if info.is_dir() or not info.filename.startswith(_CUAD_TEXT_PREFIX):
                    continue
                name = Path(info.filename).name
                if not name.endswith(".txt"):
                    continue
                (staging / name).write_bytes(bundle.read(info))
        if text_dir.exists():
            shutil.rmtree(text_dir)
        staging.replace(text_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return text_dir


def split_paragraphs(text: str) -> tuple[str, ...]:
    blocks = (re.sub(r"\s+", " ", block).strip() for block in re.split(r"\n\s*\n", text))
    return tuple(block for block in blocks if block)


def load_cuad(text_dir: Path, *, limit: int | None, seed: int) -> list[SourceContract]:
    paths = sorted(text_dir.glob("*.txt"), key=lambda path: path.name)
    random.Random(seed).shuffle(paths)
    if limit is not None:
        paths = paths[:limit]
    return [
        SourceContract(
            source="cuad",
            contract_id=path.stem,
            language="en",
            paragraphs=split_paragraphs(path.read_text(encoding="utf-8", errors="replace")),
            declared_edit=None,
        )
        for path in paths
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_if_empty(directory: Path) -> None:
    if directory.is_dir() and not any(directory.iterdir()):
        directory.rmdir()
