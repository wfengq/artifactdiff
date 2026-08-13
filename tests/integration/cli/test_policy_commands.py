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


def test_policy_validate_prints_the_resolved_clause_identifier(tmp_path: Path) -> None:
    """Returning a selector fingerprint instead of a clause ID misleads human policy review."""
    baseline = make_docx(
        tmp_path / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    policy = tmp_path / "policy.json"
    create = runner.invoke(
        app,
        [
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
        ],
    )
    result = runner.invoke(app, ["policy", "validate", str(baseline), str(policy)])

    assert create.exit_code == 0, create.stderr
    assert result.exit_code == 0, result.stderr
    assert "clause_id=clause-" in result.stdout


def test_force_output_preserves_existing_policy_when_the_write_fails(
    tmp_path: Path, monkeypatch
) -> None:
    """Removing a policy before a failed replacement destroys an approved draft."""
    baseline = make_docx(
        tmp_path / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    policy = tmp_path / "policy.json"
    policy.write_bytes(b"approved-policy")

    def fail_write(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr("artifactdiff.application.write_policy", fail_write)
    result = runner.invoke(
        app,
        [
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
            "--force-output",
        ],
    )

    assert result.exit_code == 2
    assert policy.read_bytes() == b"approved-policy"
    assert "Traceback" not in result.output
