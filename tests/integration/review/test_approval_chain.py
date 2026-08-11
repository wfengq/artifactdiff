from __future__ import annotations

import dataclasses
import os
import shutil
import stat
import time
from pathlib import Path

import pytest

from artifactdiff.bundle import verify_review_bundle, write_review_bundle
from artifactdiff.errors import ApprovalError
from artifactdiff.review import (
    approve_finding,
    list_findings,
    load_effective_verdict,
)
from artifactdiff.verification import (
    Finding,
    FindingEvidence,
    FindingOutcome,
    RawVerdict,
    finding_id,
)


def _finding(*, outcome: FindingOutcome, approvable: bool, location: str) -> Finding:
    return Finding(
        id=finding_id(
            rule_id="contract-safe.allow",
            rule_version="1.0",
            location=location,
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
        ),
        rule_id="contract-safe.allow",
        outcome=outcome,
        location=location,
        evidence=FindingEvidence(
            before_fingerprint="a" * 64,
            after_fingerprint="b" * 64,
        ),
        remediation="Review this exact finding.",
        approvable=approvable,
    )


def _bundle_with_findings(bundle_fixture: object, *findings: Finding) -> Path:
    outcome = (
        FindingOutcome.FAIL
        if any(item.outcome is FindingOutcome.FAIL for item in findings)
        else FindingOutcome.REVIEW
        if any(item.outcome is FindingOutcome.REVIEW for item in findings)
        else FindingOutcome.PASS
    )
    verdict = RawVerdict(
        outcome=outcome,
        policy_sha256=bundle_fixture.frozen.canonical_sha256,
        baseline_sha256=bundle_fixture.run.facts.baseline_sha256,
        candidate_sha256=bundle_fixture.run.facts.candidate_sha256,
        findings=list(findings),
    )
    run = dataclasses.replace(bundle_fixture.run, result=verdict)
    return write_review_bundle(**{**bundle_fixture.local_args(), "run": run})


def _run_with_findings(bundle_fixture: object, *findings: Finding) -> object:
    outcome = (
        FindingOutcome.FAIL
        if any(item.outcome is FindingOutcome.FAIL for item in findings)
        else FindingOutcome.REVIEW
        if any(item.outcome is FindingOutcome.REVIEW for item in findings)
        else FindingOutcome.PASS
    )
    verdict = RawVerdict(
        outcome=outcome,
        policy_sha256=bundle_fixture.frozen.canonical_sha256,
        baseline_sha256=bundle_fixture.run.facts.baseline_sha256,
        candidate_sha256=bundle_fixture.run.facts.candidate_sha256,
        findings=list(findings),
    )
    return dataclasses.replace(bundle_fixture.run, result=verdict)


def test_approving_each_review_finding_changes_effective_verdict_to_pass(
    bundle_fixture: object,
) -> None:
    first = _finding(outcome=FindingOutcome.REVIEW, approvable=True, location="clause:first")
    second = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:second",
    )
    bundle = _bundle_with_findings(bundle_fixture, first, second)

    assert [item.id for item in list_findings(bundle)] == [first.id, second.id]
    before = load_effective_verdict(bundle, trust_store=bundle_fixture.trust_store)
    assert before.outcome is FindingOutcome.REVIEW

    approve_finding(
        bundle,
        first.id,
        "Reviewed against the signed instruction.",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )
    middle = load_effective_verdict(bundle, trust_store=bundle_fixture.trust_store)
    assert middle.outcome is FindingOutcome.REVIEW
    approve_finding(
        bundle,
        second.id,
        "Reviewed against the signed instruction.",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )

    effective = load_effective_verdict(bundle, trust_store=bundle_fixture.trust_store)
    assert effective.outcome is FindingOutcome.PASS
    assert effective.approved_finding_ids == sorted([first.id, second.id])
    assert verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store).valid is True


def test_fail_finding_cannot_be_approved(bundle_fixture: object) -> None:
    finding = _finding(outcome=FindingOutcome.FAIL, approvable=False, location="clause:fail")
    bundle = _bundle_with_findings(bundle_fixture, finding)

    with pytest.raises(ApprovalError, match="fail findings cannot be approved"):
        approve_finding(
            bundle,
            finding.id,
            "Accept anyway.",
            signer=bundle_fixture.approver_signer,
            trust_store=bundle_fixture.trust_store,
        )


def test_approval_event_tamper_invalidates_the_bundle(bundle_fixture: object) -> None:
    finding = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:tamper",
    )
    bundle = _bundle_with_findings(bundle_fixture, finding)
    event = approve_finding(
        bundle,
        finding.id,
        "Reviewed against the signed instruction.",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )
    event_path = bundle / "events" / f"{event.sequence:06d}-approval.json"
    event_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    event_path.write_bytes(event_path.read_bytes() + b" ")

    assert verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store).valid is False


def test_same_finding_cannot_receive_a_second_decision(bundle_fixture: object) -> None:
    finding = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:duplicate",
    )
    bundle = _bundle_with_findings(bundle_fixture, finding)
    arguments = {
        "bundle": bundle,
        "finding_id": finding.id,
        "reason": "Reviewed against the signed instruction.",
        "signer": bundle_fixture.approver_signer,
        "trust_store": bundle_fixture.trust_store,
    }
    approve_finding(**arguments)

    with pytest.raises(ApprovalError, match="already has a decision"):
        approve_finding(**arguments)


def test_existing_lock_is_not_removed_by_a_failed_approval(bundle_fixture: object) -> None:
    finding = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:locked",
    )
    bundle = _bundle_with_findings(bundle_fixture, finding)
    lock = bundle / "events" / ".events.lock"
    lock.write_text('{"nonce":"other","pid":999999}', encoding="ascii")

    with pytest.raises(ApprovalError, match="locked"):
        approve_finding(
            bundle,
            finding.id,
            "Reviewed against the signed instruction.",
            signer=bundle_fixture.approver_signer,
            trust_store=bundle_fixture.trust_store,
        )

    assert lock.read_text(encoding="ascii") == '{"nonce":"other","pid":999999}'


def test_stale_lock_from_a_dead_process_is_safely_reclaimed(
    bundle_fixture: object,
) -> None:
    finding = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:stale-lock",
    )
    bundle = _bundle_with_findings(bundle_fixture, finding)
    lock = bundle / "events" / ".events.lock"
    lock.write_text(
        '{"nonce":"0123456789abcdef0123456789abcdef","pid":999999}',
        encoding="ascii",
    )
    stale = time.time() - 31
    os.utime(lock, (stale, stale))

    event = approve_finding(
        bundle,
        finding.id,
        "Reviewed after recovering a stale lock.",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )

    assert event.finding_id == finding.id
    assert not lock.exists()


def test_agent_identity_cannot_approve_a_finding(bundle_fixture: object) -> None:
    finding = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:agent",
    )
    bundle = _bundle_with_findings(bundle_fixture, finding)
    agent_identity = bundle_fixture.approver_signer.identity.model_copy(
        update={"subject_type": "agent"}
    )
    agent_signer = dataclasses.replace(
        bundle_fixture.approver_signer,
        identity=agent_identity,
    )
    agent_store = bundle_fixture.trust_store.model_copy(
        update={
            "identities": [
                agent_identity if identity.id == agent_identity.id else identity
                for identity in bundle_fixture.trust_store.identities
            ]
        }
    )

    with pytest.raises(ApprovalError, match="human identity"):
        approve_finding(
            bundle,
            finding.id,
            "Agent attempted to approve this finding.",
            signer=agent_signer,
            trust_store=agent_store,
        )


def test_verified_bundle_approval_continues_after_session_event(
    bundle_fixture: object,
) -> None:
    finding = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:verified",
    )
    arguments = bundle_fixture.verified_args(manifest_signer=bundle_fixture.archive_signer)
    arguments["run"] = _run_with_findings(bundle_fixture, finding)
    bundle = write_review_bundle(**arguments)

    event = approve_finding(
        bundle,
        finding.id,
        "Reviewed against the signed instruction.",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )

    assert event.sequence == 2
    assert verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store).valid is True


@pytest.mark.parametrize("attack", ["delete", "reorder", "duplicate"])
def test_approval_chain_rejects_delete_reorder_and_duplicate(
    bundle_fixture: object,
    attack: str,
) -> None:
    first = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location=f"clause:{attack}:first",
    )
    second = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location=f"clause:{attack}:second",
    )
    bundle = _bundle_with_findings(bundle_fixture, first, second)
    for finding in (first, second):
        approve_finding(
            bundle,
            finding.id,
            "Reviewed against the signed instruction.",
            signer=bundle_fixture.approver_signer,
            trust_store=bundle_fixture.trust_store,
        )
    first_path = bundle / "events" / "000001-approval.json"
    second_path = bundle / "events" / "000002-approval.json"
    first_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    second_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    first_bytes = first_path.read_bytes()
    second_bytes = second_path.read_bytes()
    if attack == "delete":
        first_path.unlink()
    elif attack == "reorder":
        first_path.write_bytes(second_bytes)
        second_path.write_bytes(first_bytes)
    else:
        second_path.write_bytes(first_bytes)

    assert verify_review_bundle(bundle, trust_store=bundle_fixture.trust_store).valid is False


def test_approval_event_cannot_be_replayed_into_another_bundle(
    bundle_fixture: object,
) -> None:
    shared = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:shared",
    )
    extra = _finding(
        outcome=FindingOutcome.REVIEW,
        approvable=True,
        location="clause:extra",
    )
    source = _bundle_with_findings(bundle_fixture, shared)
    target = _bundle_with_findings(bundle_fixture, shared, extra)
    approve_finding(
        source,
        shared.id,
        "Reviewed against the signed instruction.",
        signer=bundle_fixture.approver_signer,
        trust_store=bundle_fixture.trust_store,
    )
    shutil.copyfile(
        source / "events" / "000001-approval.json",
        target / "events" / "000001-approval.json",
    )

    assert verify_review_bundle(target, trust_store=bundle_fixture.trust_store).valid is False
