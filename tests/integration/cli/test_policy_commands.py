import json
from pathlib import Path

import yaml
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
    assert result.exit_code == 0, result.output
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


def test_policy_create_prompts_each_missing_field_once_and_writes_a_valid_policy(
    tmp_path: Path, monkeypatch
) -> None:
    """Skipping a field prompt would create a policy whose exact replacement cannot be reviewed."""
    baseline = make_docx(
        tmp_path / "baseline.docx",
        heading="Section 4 Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    policy = tmp_path / "prompted.json"
    answers = iter(
        [
            "section 4",
            "Payment Terms",
            "Payment is due within 30 days.",
            "payment-window",
            "30 days",
            "45 days",
        ]
    )
    prompts: list[str] = []

    monkeypatch.setattr("typer.testing._NamedTextIOWrapper.isatty", lambda _self: True)
    original_prompt = __import__("artifactdiff.cli_policy", fromlist=["typer"]).typer.prompt

    def prompted(label: str) -> str:
        prompts.append(label)
        return original_prompt(label)

    monkeypatch.setattr("artifactdiff.cli_policy.typer.prompt", prompted)
    result = runner.invoke(
        app,
        ["policy", "create", str(baseline), "--output", str(policy)],
        input="\n".join(answers) + "\n",
    )

    assert result.exit_code == 0, result.output
    assert prompts == ["clause", "heading", "anchor", "rule-id", "before", "after"]
    payload = json.loads(policy.read_text(encoding="utf-8"))
    assert payload["profile"] == "contract-safe"
    assert payload["expect"][0]["operation"] == {
        "after": "45 days",
        "before": "30 days",
        "occurrences": 1,
        "type": "exact_replace",
    }


def test_policy_create_yaml_is_equivalent_to_canonical_json(tmp_path: Path) -> None:
    """Changing YAML serialization must not change the contract-safe policy represented on disk."""
    baseline = make_docx(
        tmp_path / "baseline.docx",
        heading="Payment Terms",
        paragraphs=["Payment is due within 30 days."],
        rows=[["Column"]],
    )
    arguments = [
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
    json_policy = tmp_path / "policy.json"
    yaml_policy = tmp_path / "policy.yaml"

    json_result = runner.invoke(
        app, ["policy", "create", str(baseline), "--output", str(json_policy), *arguments]
    )
    yaml_result = runner.invoke(
        app, ["policy", "create", str(baseline), "--output", str(yaml_policy), *arguments]
    )
    repeated = runner.invoke(
        app, ["policy", "create", str(baseline), "--output", str(yaml_policy), *arguments]
    )

    assert json_result.exit_code == 0, json_result.stderr
    assert yaml_result.exit_code == 0, yaml_result.stderr
    assert yaml.safe_load(yaml_policy.read_text(encoding="utf-8")) == json.loads(
        json_policy.read_text(encoding="utf-8")
    )
    assert repeated.exit_code == 2
