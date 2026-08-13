from typer.testing import CliRunner

from artifactdiff.cli import app

runner = CliRunner()


def test_sealed_bundle_pack_requires_a_recipient() -> None:
    """Allowing an unaddressed sealed archive would discard its confidentiality guarantee."""
    result = runner.invoke(app, ["bundle", "pack", "bundle", "archive.tar.age", "--mode", "sealed"])

    assert result.exit_code == 2
    assert "recipient" in result.stderr.casefold()
