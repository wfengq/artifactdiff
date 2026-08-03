from pathlib import Path

from artifactdiff.normalize import fingerprint, normalize_text, sha256_file


def test_normalize_text_is_deterministic() -> None:
    assert normalize_text("  Hello\u00a0  WORLD\r\n") == "hello world"
    assert fingerprint("Hello world") == fingerprint(" hello   WORLD ")


def test_sha256_file_returns_content_hash(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    source.write_bytes(b"ArtifactDiff")

    assert sha256_file(source) == "8c2ecd3ed3050df33f38ca80708fdb37729e98a8fb7422b5cea0ac4ed80c170a"
