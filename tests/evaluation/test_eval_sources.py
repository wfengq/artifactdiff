from pathlib import Path

import pytest

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
from artifactdiff.trust import TrustStore
from evaluation.models import Format
from evaluation.render import render
from evaluation.sources import load_synthetic


def test_synthetic_seeds_load_with_declared_edits() -> None:
    seeds = load_synthetic()
    assert [seed.contract_id for seed in seeds] == [
        "en-services",
        "en-supply",
        "zh-purchase",
        "zh-services",
    ]
    for seed in seeds:
        edit = seed.declared_edit
        assert seed.source == "synthetic"
        assert edit is not None
        assert seed.paragraphs[edit.paragraph_index].count(edit.before) == 1
        assert sum(paragraph.count(edit.before) for paragraph in seed.paragraphs) == 1
        assert not any(edit.after in paragraph for paragraph in seed.paragraphs)


@pytest.mark.parametrize("fmt", list(Format))
def test_synthetic_declared_edits_draft_valid_policies(tmp_path: Path, fmt: Format) -> None:
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    for seed in load_synthetic():
        edit = seed.declared_edit
        assert edit is not None
        baseline = tmp_path / f"{seed.contract_id}.{fmt.value}"
        render(seed.paragraphs, baseline, fmt=fmt, language=seed.language)
        application.draft_policy(
            baseline,
            ClauseSelector(clause_label=edit.clause_label, heading=edit.heading, anchor=edit.anchor),
            before=edit.before,
            after=edit.after,
            rule_id="authorized",
        )


def test_seed_with_ambiguous_before_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text(
        "id: bad\nlanguage: en\nlicense: CC0-1.0\n"
        "paragraphs:\n  - 'Pay within 30 days.'\n  - 'Deliver within 30 days.'\n"
        "edit: {before: '30 days', after: '45 days', clause_label: '', heading: '', anchor: 'Pay'}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exactly one paragraph"):
        load_synthetic(tmp_path)
