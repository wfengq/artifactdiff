from reportlab.pdfgen.canvas import Canvas
from typer.testing import CliRunner

from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.cli import app
from artifactdiff.cli_support import _PromptSecret
from artifactdiff.contract import ClauseSelector
from artifactdiff.trust import TrustStore

runner = CliRunner()


def test_review_is_a_discoverable_lazy_adapter_boundary() -> None:
    """Replacing the deferred desk boundary with a traceback leaks implementation state."""
    result = runner.invoke(app, ["review", "--no-open"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "not available" in result.stderr


def test_private_key_prompt_is_directed_to_stderr_for_json_commands(monkeypatch) -> None:
    """Writing an interactive signing prompt to stdout corrupts a JSON response stream."""
    observed: dict[str, object] = {}

    monkeypatch.setattr("artifactdiff.cli_support.sys.stdin.isatty", lambda: True)

    def prompt(_text: str, **kwargs: object) -> str:
        observed.update(kwargs)
        return "passphrase"

    monkeypatch.setattr("artifactdiff.cli_support.typer.prompt", prompt)

    assert _PromptSecret().get_secret("archive") == b"passphrase"
    assert observed["err"] is True


def _sealed_exact_policy(baseline, root):
    application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
    policy = application.draft_policy(
        baseline,
        ClauseSelector(
            clause_label="",
            heading="",
            anchor="Payment is due within 30 days.",
        ),
        rule_id="payment-window",
        before="30 days",
        after="45 days",
    )
    policy_path = application.write_policy(policy, root / "policy.json")
    return application.seal_policy(baseline, policy_path, root / "sealed.json")


def _pdf(path, lines, *, y_origin: int = 720):
    canvas = Canvas(str(path))
    for offset, line in enumerate(lines):
        canvas.drawString(72, y_origin - 20 * offset, line)
    canvas.save()
    return path


def test_verify_exit_codes_follow_effective_verdict(tmp_path) -> None:
    """Returning zero for a review or fail finding would allow an unsafe change through CI."""
    baseline = _pdf(tmp_path / "baseline.pdf", ["Payment Terms", "Payment is due within 30 days."])
    exact = _pdf(tmp_path / "exact.pdf", ["Payment Terms", "Payment is due within 45 days."])
    reflow = _pdf(
        tmp_path / "reflow.pdf",
        ["Payment Terms", "Payment is due within 45 days."],
        y_origin=680,
    )
    party_change = _pdf(
        tmp_path / "party-change.pdf",
        ["Payment Terms", "Acme Corporation agrees payment is due within 45 days."],
    )
    sealed = _sealed_exact_policy(baseline, tmp_path)

    passing = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(exact),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "exact-bundle"),
        ],
    )
    failing = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(party_change),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "party-bundle"),
        ],
    )
    review = runner.invoke(
        app,
        [
            "verify",
            str(baseline),
            str(reflow),
            "--policy",
            str(sealed),
            "--output",
            str(tmp_path / "reflow-bundle"),
        ],
    )

    assert passing.exit_code == 0, passing.stderr
    assert review.exit_code == 1, review.stderr
    assert failing.exit_code == 1, failing.stderr
