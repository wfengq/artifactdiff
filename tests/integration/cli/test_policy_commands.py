import json
from pathlib import Path

from typer.testing import CliRunner

from artifactdiff.cli import app
from tests.factories import make_docx

runner = CliRunner()


def test_contract_cli_commands_are_discoverable() -> None:
    """Removing a public contract command must fail CLI discovery."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in (
        "compare",
        "inspect",
        "policy",
        "session",
        "verify",
        "review",
        "approve",
        "bundle",
    ):
        assert command in result.stdout


def test_policy_create_writes_contract_safe_json_and_refuses_overwrite(tmp_path: Path) -> None:
    """Dropping the force guard could silently replace an approved draft."""
    baseline = make_docx(
        tmp_path / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    policy = tmp_path / "policy.json"
    arguments = [
        "policy",
        "create",
        str(baseline),
        "--output",
        str(policy),
        "--rule-id",
        "payment-window",
        "--clause",
        "",
        "--heading",
        "Payment Terms",
        "--anchor",
        "Payment is due within 30 days.",
        "--before",
        "30 days",
        "--after",
        "45 days",
    ]

    created = runner.invoke(app, arguments)
    original = policy.read_bytes()
    repeated = runner.invoke(app, arguments)

    assert created.exit_code == 0, created.stderr
    assert json.loads(policy.read_text(encoding="utf-8"))["profile"] == "contract-safe"
    assert repeated.exit_code == 2
    assert policy.read_bytes() == original
