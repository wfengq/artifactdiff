from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from artifactdiff.bundle import write_review_bundle
from artifactdiff.bundle.digests import canonical_bytes
from artifactdiff.errors import BundleError
from artifactdiff.evidence import EvidenceIndex, EvidenceItem, EvidenceKind
from artifactdiff.policy import EvidenceMode
from artifactdiff.reporting.contract_html import write_contract_html
from artifactdiff.review import approve_finding
from artifactdiff.verification import (
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
)


def _bundle(bundle_fixture: object, *, verified: bool = True, evidence: Path | None = None) -> Path:
    arguments = (
        bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
        if verified
        else bundle_fixture.local_args()
    )
    if evidence is not None:
        arguments["evidence"] = evidence
    return write_review_bundle(**arguments)


def _evidence(root: Path, mode: EvidenceMode, items: list[tuple[EvidenceKind, str, bytes]]) -> Path:
    evidence = root / "evidence"
    models: list[EvidenceItem] = []
    for kind, relative, contents in items:
        path = evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        models.append(
            EvidenceItem(
                kind=kind,
                path=relative,
                sha256=hashlib.sha256(contents).hexdigest(),
                size_bytes=len(contents),
            )
        )
    index = EvidenceIndex(mode=mode, items=sorted(models, key=lambda item: item.path))
    (evidence / "index.json").write_bytes(canonical_bytes(index))
    return evidence


def _review_bundle(bundle_fixture: object, location: str = "Payment clause") -> tuple[Path, str]:
    finding_id = "finding-" + "1" * 24
    finding = Finding(
        id=finding_id,
        rule_id="display-rule",
        outcome=FindingOutcome.REVIEW,
        location=location,
        evidence=FindingEvidence(before_excerpt=location, after_excerpt="safe"),
        remediation="Review this change",
        approvable=True,
    )
    verdict = RawVerdict(
        outcome=FindingOutcome.REVIEW,
        policy_sha256=bundle_fixture.frozen.canonical_sha256,
        baseline_sha256=bundle_fixture.run.result.baseline_sha256,
        candidate_sha256=bundle_fixture.run.result.candidate_sha256,
        findings=[finding],
    )
    run = bundle_fixture.run.__class__(
        result=verdict,
        facts=bundle_fixture.run.facts,
        comparison=bundle_fixture.run.comparison,
        json_path=bundle_fixture.run.json_path,
        visual_assets={},
    )
    arguments = bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    arguments["run"] = run
    return write_review_bundle(**arguments), finding_id


def test_contract_report_is_offline_escaped_and_assurance_visible(
    bundle_fixture: object, tmp_path: Path
) -> None:
    malicious = "<script>alert(1)</script>"
    # Put attacker text in an explicitly displayable, bounded finding field.
    bundle, _ = _review_bundle(bundle_fixture, malicious)

    report = write_contract_html(
        bundle, tmp_path / "review.html", trust_store=bundle_fixture.trust_store
    )
    html = report.read_text(encoding="utf-8")
    document = BeautifulSoup(html, "html.parser")

    assert "VERIFIED" in document.get_text(" ", strip=True)
    assert "Raw verdict" in html and "Effective verdict" in html
    assert "https://" not in html and "http://" not in html and "file:" not in html
    assert malicious not in html
    assert malicious in document.get_text(" ", strip=True)
    assert document.find("script") is None
    assert document.find("form") is None
    assert not any(
        "approve" in button.get_text(" ", strip=True).casefold()
        for button in document.find_all("button")
    )


def test_contract_report_renders_signed_approval_and_effective_verdict(
    bundle_fixture: object, tmp_path: Path
) -> None:
    bundle, finding_id = _review_bundle(bundle_fixture)
    approve_finding(
        bundle,
        finding_id,
        "Authorized reflow reviewed against the signed instruction",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )

    report = write_contract_html(
        bundle, tmp_path / "review.html", trust_store=bundle_fixture.trust_store
    )
    text = BeautifulSoup(report.read_text("utf-8"), "html.parser").get_text(" ", strip=True)

    assert "Raw verdict REVIEW" in text
    assert "Effective verdict PASS" in text
    assert finding_id in text
    assert "Authorized reflow reviewed against the signed instruction" in text
    assert "bundle-human-approver" in text


def test_contract_report_is_deterministic_and_legacy_report_is_unchanged(
    bundle_fixture: object, tmp_path: Path
) -> None:
    bundle = _bundle(bundle_fixture)
    legacy = Path("src/artifactdiff/reporting/template.html").read_bytes()

    first = write_contract_html(
        bundle, tmp_path / "first.html", trust_store=bundle_fixture.trust_store
    )
    second = write_contract_html(
        bundle, tmp_path / "second.html", trust_store=bundle_fixture.trust_store
    )

    assert first.read_bytes() == second.read_bytes()
    assert Path("src/artifactdiff/reporting/template.html").read_bytes() == legacy


@pytest.mark.parametrize("mode", [EvidenceMode.MINIMAL, EvidenceMode.FULL])
def test_contract_report_embeds_only_evidence_authorized_by_mode(
    bundle_fixture: object, tmp_path: Path, mode: EvidenceMode
) -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"bounded-image"
    items = [(EvidenceKind.CHANGED_REGION, "regions/crop.png", png)]
    if mode is EvidenceMode.FULL:
        items.append((EvidenceKind.FULL_PAGE, "pages/page.png", png))
    evidence = _evidence(tmp_path / mode.value, mode, items)
    bundle = _bundle(bundle_fixture, verified=False, evidence=evidence)

    html = write_contract_html(
        bundle, tmp_path / f"{mode.value}.html", trust_store=bundle_fixture.trust_store
    ).read_text(encoding="utf-8")
    document = BeautifulSoup(html, "html.parser")
    images = document.find_all("img")

    assert any(image.get("data-evidence-kind") == "changed_region" for image in images)
    assert any(image.get("data-evidence-kind") == "full_page" for image in images) is (
        mode is EvidenceMode.FULL
    )
    assert all(str(image.get("src", "")).startswith("data:image/png;base64,") for image in images)


def test_contract_report_warns_when_visual_evidence_is_unavailable(
    bundle_fixture: object, tmp_path: Path
) -> None:
    bundle = _bundle(bundle_fixture, verified=False)

    report = write_contract_html(
        bundle, tmp_path / "review.html", trust_store=bundle_fixture.trust_store
    )
    document = BeautifulSoup(report.read_text("utf-8"), "html.parser")

    assert "visual evidence is unavailable" in document.get_text(" ", strip=True).casefold()


def test_contract_report_rejects_tampered_bundle_before_writing(
    bundle_fixture: object, tmp_path: Path
) -> None:
    bundle = _bundle(bundle_fixture, verified=False)
    verdict = bundle / "core" / "verdict.json"
    verdict.chmod(0o600)
    verdict.write_bytes(verdict.read_bytes() + b" ")
    output = tmp_path / "review.html"

    with pytest.raises(BundleError, match="verification"):
        write_contract_html(bundle, output, trust_store=bundle_fixture.trust_store)

    assert not output.exists()


def test_contract_report_rejects_symlinked_bundle_or_evidence(
    bundle_fixture: object, tmp_path: Path
) -> None:
    bundle = _bundle(bundle_fixture, verified=False)
    alias = tmp_path / "bundle-link"
    try:
        alias.symlink_to(bundle, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(BundleError):
        write_contract_html(alias, tmp_path / "review.html", trust_store=bundle_fixture.trust_store)


def test_contract_report_refuses_oversize_evidence(bundle_fixture: object, tmp_path: Path) -> None:
    contents = b"\x89PNG\r\n\x1a\n" + (b"x" * (5 * 1024 * 1024))
    evidence = _evidence(
        tmp_path / "oversize",
        EvidenceMode.MINIMAL,
        [(EvidenceKind.CHANGED_REGION, "crop.png", contents)],
    )
    bundle = _bundle(bundle_fixture, verified=False, evidence=evidence)
    with pytest.raises(BundleError, match="evidence"):
        write_contract_html(
            bundle, tmp_path / "review.html", trust_store=bundle_fixture.trust_store
        )


def test_contract_report_rejects_a_valid_event_appended_during_snapshot(
    bundle_fixture: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from artifactdiff.reporting import contract_html

    bundle, finding_id = _review_bundle(bundle_fixture)
    original = contract_html.validate_approval_event_snapshot

    def validate_then_append(*args: object, **kwargs: object) -> object:
        effective = original(*args, **kwargs)
        approve_finding(
            bundle,
            finding_id,
            "Concurrent valid approval must not be omitted from the report snapshot",
            signer=bundle_fixture.approver_signer,
            trust_store=bundle_fixture.trust_store,
        )
        return effective

    monkeypatch.setattr(contract_html, "validate_approval_event_snapshot", validate_then_append)

    with pytest.raises(BundleError, match="changed"):
        write_contract_html(
            bundle, tmp_path / "review.html", trust_store=bundle_fixture.trust_store
        )
