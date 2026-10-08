"""Source contracts: committed synthetic seeds and the CUAD v1 corpus."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

from evaluation.models import AuthorizedEdit, Language, SourceContract

SYNTHETIC_DIR = Path(__file__).parent / "corpus" / "synthetic"


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
