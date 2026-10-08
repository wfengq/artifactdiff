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


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_fetch_cuad_rejects_checksum_mismatch_and_leaves_nothing(tmp_path: Path) -> None:
    import io

    from evaluation.sources import CuadChecksumError, fetch_cuad

    with pytest.raises(CuadChecksumError):
        fetch_cuad(tmp_path, opener=lambda url: io.BytesIO(b"not a zip"))
    assert not [path for path in tmp_path.rglob("*") if path.is_file()]
    assert not (tmp_path / "generated" / "cuad").exists()


def test_fetch_cuad_extracts_only_txt_from_verified_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    import evaluation.sources as sources

    payload = _zip_bytes(
        {
            "CUAD_v1/full_contract_txt/a.txt": b"Alpha agreement.",
            "CUAD_v1/full_contract_pdf/a.pdf": b"%PDF-1.4",
            "CUAD_v1/CUAD_v1.json": b"{}",
        }
    )
    archive = tmp_path / "download.zip"
    archive.write_bytes(payload)
    monkeypatch.setattr(sources, "CUAD_SHA256", hashlib.sha256(payload).hexdigest())

    text_dir = sources.fetch_cuad(tmp_path / "data", archive=archive)

    assert text_dir == tmp_path / "data" / "generated" / "cuad"
    assert sorted(path.name for path in text_dir.iterdir()) == ["a.txt"]
    assert (tmp_path / "data" / "raw" / "CUAD_v1.zip").read_bytes() == payload


def test_split_paragraphs_collapses_whitespace() -> None:
    from evaluation.sources import split_paragraphs

    assert split_paragraphs("A  b\n c\n\n\n D\n") == ("A b c", "D")


def test_load_cuad_handles_unicode_and_punctuation_names(tmp_path: Path) -> None:
    from evaluation.sources import load_cuad

    names = [
        "LECLANCHÉ S.A. - JOINT DEVELOPMENT AND MARKETING AGREEMENT.txt",
        "A, B & C.txt",
    ]
    for name in names:
        (tmp_path / name).write_text("Heading\n\nBody text here.", encoding="utf-8")
    contracts = load_cuad(tmp_path, limit=None, seed=0)
    assert sorted(contract.contract_id for contract in contracts) == sorted(
        Path(name).stem for name in names
    )
    assert all(contract.source == "cuad" and contract.language == "en" for contract in contracts)
    assert all(contract.paragraphs == ("Heading", "Body text here.") for contract in contracts)
    assert all(contract.declared_edit is None for contract in contracts)


def test_load_cuad_sampling_is_seeded_and_limited(tmp_path: Path) -> None:
    from evaluation.sources import load_cuad

    for index in range(20):
        (tmp_path / f"c{index:02d}.txt").write_text(f"Contract {index}.", encoding="utf-8")
    first = [c.contract_id for c in load_cuad(tmp_path, limit=5, seed=0)]
    again = [c.contract_id for c in load_cuad(tmp_path, limit=5, seed=0)]
    other = [c.contract_id for c in load_cuad(tmp_path, limit=20, seed=1)]
    assert first == again
    assert len(first) == 5
    assert other != [c.contract_id for c in load_cuad(tmp_path, limit=20, seed=0)]
