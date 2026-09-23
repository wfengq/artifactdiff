from __future__ import annotations

import re
from pathlib import Path


def test_readme_explains_the_product_demo_and_current_limits() -> None:
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    folded = readme.casefold()

    assert readme.startswith("# ArtifactDiff")
    assert "ai agent" in folded
    assert "docx" in folded and "pdf" in folded
    assert all(outcome in readme for outcome in ("PASS", "REVIEW", "FAIL"))
    assert 'pip install -e ".[dev]"' in readme
    assert "python scripts/run_contract_golden_path.py" in readme
    assert "python -m json.tool" in readme
    assert "review` blocks delivery by default" in folded
    assert "offline" in folded and "ed25519" in folded and "review bundle" in folded
    assert "artifactdiff review" in readme
    assert "artifactdiff-mcp" in readme
    assert "does not perform ocr" in folded
    assert "multi-column" in folded
    assert "not legal approval" in folded


def test_readme_local_links_resolve_inside_the_repository() -> None:
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    local_targets = [
        target.split("#", maxsplit=1)[0]
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", readme)
        if not target.startswith(("http://", "https://", "#"))
    ]

    assert local_targets
    assert all((root / target).exists() for target in local_targets)
