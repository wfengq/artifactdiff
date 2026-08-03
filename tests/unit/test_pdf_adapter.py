from pathlib import Path

import pytest
from pdfminer.pdfdocument import PDFPasswordIncorrect
from pdfplumber.utils.exceptions import PdfminerException

import artifactdiff.formats.pdf as pdf_module
from artifactdiff.errors import InputValidationError, ResourceLimitError, UnsupportedFormatError
from artifactdiff.formats import adapter_for
from artifactdiff.formats.pdf import PdfAdapter
from tests.factories import make_pdf


class FakePage:
    width = 612
    height = 792

    def extract_words(self, **kwargs: object) -> list[object]:
        assert kwargs == {'use_text_flow': True, 'keep_blank_chars': False}
        return []


class FakeDocument:
    def __init__(self, page_count: int) -> None:
        self.pages = [FakePage() for _ in range(page_count)]

    def __enter__(self) -> 'FakeDocument':
        return self

    def __exit__(self, *args: object) -> None:
        return None


def fake_large_pdf(monkeypatch: pytest.MonkeyPatch, path: Path) -> Path:
    path.write_bytes(b'%PDF-1.4')
    monkeypatch.setattr(pdf_module.pdfplumber, 'open', lambda _: FakeDocument(501))
    return path


def test_pdf_adapter_extracts_text_geometry_and_renders(tmp_path: Path) -> None:
    source = make_pdf(
        tmp_path / 'sample.pdf',
        [[(72, 720, 'Revenue 100')], [(72, 720, 'Notes')]],
    )

    snapshot = PdfAdapter().load(source, render=True, workdir=tmp_path / 'work')

    assert snapshot.page_count == 2
    assert snapshot.pages[0].text == 'Revenue 100'
    assert snapshot.pages[0].blocks[0].bbox is not None
    assert Path(snapshot.pages[0].render_path).is_file()
    source.rename(tmp_path / 'source-was-closed.pdf')


def test_pdf_adapter_preserves_reading_order_and_renders_at_144_dpi(tmp_path: Path) -> None:
    source = make_pdf(
        tmp_path / 'ordered.pdf',
        [[(200, 700, 'Second'), (72, 720, 'First'), (72, 680, 'Third')]],
    )

    snapshot = PdfAdapter().load(source, render=True, workdir=tmp_path / 'work')

    assert [block.text for block in snapshot.pages[0].blocks] == [
        'First',
        'Second',
        'Third',
    ]
    assert snapshot.pages[0].text == 'First\nSecond\nThird'

    from PIL import Image

    with Image.open(snapshot.pages[0].render_path) as image:
        assert image.mode == 'RGB'
        assert image.size == (1224, 1584)


def test_pdf_adapter_rejects_corrupt_pdf(tmp_path: Path) -> None:
    source = tmp_path / 'broken.pdf'
    source.write_bytes(b'not a pdf')

    with pytest.raises(InputValidationError, match='invalid PDF') as error:
        PdfAdapter().load(source, render=False, workdir=tmp_path / 'work')
    assert str(source) in str(error.value)


def test_pdf_adapter_identifies_encrypted_pdf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / 'encrypted.pdf'
    source.write_bytes(b'%PDF-1.4')

    def raise_encrypted(_: Path) -> None:
        raise PdfminerException(PDFPasswordIncorrect())

    monkeypatch.setattr(pdf_module.pdfplumber, 'open', raise_encrypted)

    with pytest.raises(InputValidationError, match='encrypted PDF') as error:
        PdfAdapter().load(source, render=False, workdir=tmp_path / 'work')
    assert str(source) in str(error.value)


def test_pdf_adapter_rejects_documents_over_500_pages_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fake_large_pdf(monkeypatch, tmp_path / 'large.pdf')

    with pytest.raises(ResourceLimitError, match='500 page limit'):
        PdfAdapter().load(source, render=False, workdir=tmp_path / 'work')


def test_pdf_adapter_force_allows_documents_over_500_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fake_large_pdf(monkeypatch, tmp_path / 'large.pdf')

    snapshot = PdfAdapter().load(source, render=False, workdir=tmp_path / 'work', force=True)

    assert snapshot.page_count == 501


def test_adapter_registry_selects_pdf_case_insensitively(tmp_path: Path) -> None:
    assert isinstance(adapter_for(tmp_path / 'source.PDF'), PdfAdapter)


def test_adapter_registry_rejects_unsupported_formats(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedFormatError, match='Supported formats are PDF and DOCX'):
        adapter_for(tmp_path / 'source.txt')
