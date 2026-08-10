from pathlib import Path

import pytest

from artifactdiff.errors import InputValidationError, PolicyValidationError
from artifactdiff.verification.service import VerificationOptions, verify_contract_change
from tests.integration.verification.test_service import contract_edit_fixture


def test_baseline_hash_is_rejected_before_candidate_is_parsed(tmp_path: Path) -> None:
    baseline, _, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    baseline.write_bytes(b"modified after policy freeze")
    invalid_candidate = tmp_path / "candidate.pdf"
    invalid_candidate.write_bytes(b"not a PDF")

    with pytest.raises(PolicyValidationError, match="baseline hash"):
        verify_contract_change(
            baseline,
            invalid_candidate,
            frozen,
            tmp_path / "out",
            options=VerificationOptions(visual=False),
        )


def test_pdf_to_docx_is_rejected_without_loading_either_document(tmp_path: Path) -> None:
    baseline, _, frozen = contract_edit_fixture(tmp_path, "pdf", "pdf", 30, 45)
    unsupported_candidate = tmp_path / "candidate.docx"
    unsupported_candidate.write_bytes(b"not a DOCX")

    with pytest.raises(InputValidationError, match="supported verification paths"):
        verify_contract_change(
            baseline,
            unsupported_candidate,
            frozen,
            tmp_path / "out",
            options=VerificationOptions(visual=False),
        )
