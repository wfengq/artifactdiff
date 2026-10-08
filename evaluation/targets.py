"""Choose the authorized edit for a contract and prepare its sealed policy."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from artifactdiff import inspect_contract
from artifactdiff.application import ArtifactDiffApplication
from artifactdiff.contract import ClauseSelector
from artifactdiff.normalize import normalize_text
from artifactdiff.trust import TrustStore
from evaluation.models import AuthorizedEdit, DraftFailure, Format, SourceContract
from evaluation.render import render

RULE_ID = "authorized"
_DURATION = re.compile(r"\b(\d+) (days|months|years)\b")
_PERCENTAGE = re.compile(r"\b(\d+(?:\.\d+)?)%")
_MONEY = re.compile(r"\$\s?(\d[\d,]*)")
_ANCHOR_WORDS = 6
_MIN_PRECEDING_WORDS = 3


@dataclass(frozen=True)
class PreparedContract:
    contract: SourceContract
    format: Format
    edit: AuthorizedEdit
    baseline_path: Path
    sealed_policy_path: Path
    edited_clause_chars: int
    baseline_clause_count: int
    pdf_replacements: int


def _shifted(pattern: re.Pattern[str], match: re.Match[str]) -> str:
    text = match.group()
    number = match.group(1)
    if pattern is _DURATION:
        new = str(int(number) + 15)
    elif pattern is _PERCENTAGE:
        new = format(Decimal(number) + 1, "f")
    else:
        value = int(number.replace(",", "")) + 1000
        new = f"{value:,}" if "," in number else str(value)
    start, end = match.span(1)
    return text[: start - match.start()] + new + text[end - match.start() :]


def _anchor(clause_text: str, match: re.Match[str]) -> str:
    preceding = clause_text[: match.start()].split()
    if len(preceding) >= _MIN_PRECEDING_WORDS:
        return " ".join(preceding[-_ANCHOR_WORDS:])
    return " ".join(clause_text[match.end() :].split()[:_ANCHOR_WORDS])


def choose_edit(
    contract: SourceContract, clauses: list[dict[str, object]]
) -> AuthorizedEdit | str:
    """Pick the first unambiguous duration, percentage or money edit, or a reason."""
    document = "\n".join(contract.paragraphs)
    unique_target_found = False
    for clause in clauses:
        clause_text = str(clause["text"])
        normalized_clause = normalize_text(str(clause["normalized_text"]))
        for pattern in (_DURATION, _PERCENTAGE, _MONEY):
            for match in pattern.finditer(clause_text):
                before = match.group()
                if document.count(before) != 1 or clause_text.count(before) != 1:
                    continue
                after = _shifted(pattern, match)
                if after in document:
                    continue
                unique_target_found = True
                anchor = _anchor(clause_text, match)
                if not anchor or normalized_clause.count(normalize_text(anchor)) != 1:
                    continue
                label = clause["label"]
                assert isinstance(label, dict)
                return AuthorizedEdit(
                    before=before,
                    after=after,
                    paragraph_index=next(
                        i for i, text in enumerate(contract.paragraphs) if before in text
                    ),
                    clause_label=str(label["normalized"]),
                    heading=str(clause["heading"]),
                    anchor=anchor,
                )
    return "no-unique-anchor" if unique_target_found else "no-unique-target"


def prepare(contract: SourceContract, fmt: Format, workdir: Path) -> PreparedContract | DraftFailure:
    """Render the baseline, choose the edit, then draft and seal its policy."""

    def failure(reason: str) -> DraftFailure:
        return DraftFailure(contract.source, contract.contract_id, fmt.value, reason[:200])

    try:
        workdir.mkdir(parents=True, exist_ok=True)
        baseline = workdir / f"baseline.{fmt.value}"
        replacements = render(contract.paragraphs, baseline, fmt=fmt, language=contract.language)
        clauses = inspect_contract(baseline, max_clauses=1000)["clauses"]
        assert isinstance(clauses, list)
        chosen = contract.declared_edit or choose_edit(contract, clauses)
        if isinstance(chosen, str):
            return failure(chosen)
        application = ArtifactDiffApplication(trust_store=TrustStore(identities=[]))
        policy = application.draft_policy(
            baseline,
            ClauseSelector(
                clause_label=chosen.clause_label, heading=chosen.heading, anchor=chosen.anchor
            ),
            before=chosen.before,
            after=chosen.after,
            rule_id=RULE_ID,
        )
        policy_path = application.write_policy(policy, workdir / "policy.json")
        sealed = application.seal_policy(baseline, policy_path, workdir / "sealed-policy.json")
    except Exception as error:  # noqa: BLE001 - every failure is a recorded outcome
        return failure(f"{type(error).__name__}: {error}")
    edited = [str(c["text"]) for c in clauses if chosen.before in normalize_text(str(c["text"]))]
    return PreparedContract(
        contract=contract,
        format=fmt,
        edit=chosen,
        baseline_path=baseline,
        sealed_policy_path=sealed,
        edited_clause_chars=len(edited[0]) if edited else 0,
        baseline_clause_count=len(clauses),
        pdf_replacements=replacements,
    )


def prepared_dir(root: Path, contract: SourceContract, fmt: Format) -> Path:
    """A short, filesystem-safe working directory for one contract and format."""
    digest = hashlib.sha256(f"{contract.source}\0{contract.contract_id}".encode()).hexdigest()
    return root / f"{digest[:16]}-{fmt.value}"
