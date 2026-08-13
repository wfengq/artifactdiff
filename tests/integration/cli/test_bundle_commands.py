from typer.testing import CliRunner

from artifactdiff.bundle import write_review_bundle
from artifactdiff.cli import app

runner = CliRunner()


def test_sealed_bundle_pack_requires_a_recipient() -> None:
    """Allowing an unaddressed sealed archive would discard its confidentiality guarantee."""
    result = runner.invoke(app, ["bundle", "pack", "bundle", "archive.tar.age", "--mode", "sealed"])

    assert result.exit_code == 2
    assert "recipient" in result.stderr.casefold()


def test_tampered_bundle_is_a_nondisclosing_public_error(bundle_fixture: object) -> None:
    """Returning tampered bundle bytes could disclose protected contract text to a terminal."""
    bundle = write_review_bundle(**bundle_fixture.local_args())
    verdict = bundle / "core" / "verdict.json"
    verdict.chmod(0o600)
    verdict.write_text("SECRET CONTRACT TERM", encoding="utf-8")

    result = runner.invoke(app, ["bundle", "verify", str(bundle)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "SECRET CONTRACT TERM" not in result.output
