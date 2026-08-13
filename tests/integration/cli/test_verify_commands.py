from typer.testing import CliRunner

from artifactdiff.cli import app

runner = CliRunner()


def test_review_is_a_discoverable_lazy_adapter_boundary() -> None:
    """Replacing the deferred desk boundary with a traceback leaks implementation state."""
    result = runner.invoke(app, ["review", "--no-open"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "not available" in result.stderr
