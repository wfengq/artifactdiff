import json
from pathlib import Path

import pytest
from pdfminer.pdfdocument import PDFPasswordIncorrect
from pdfplumber.utils.exceptions import PdfminerException

import artifactdiff.formats.pdf as pdf_module
from artifactdiff.errors import InputValidationError, ResourceLimitError, UnsupportedFormatError
from artifactdiff.formats import adapter_for
from artifactdiff.formats.pdf import PdfAdapter
from artifactdiff.models import PageSnapshot
from tests.factories import make_pdf


class FakePage:
    width = 612
    height = 792

    def __init__(self) -> None:
        self.annots: list[object] = []
        self.images: list[object] = []

    def extract_words(self, **kwargs: object) -> list[object]:
        assert kwargs == {'use_text_flow': True, 'keep_blank_chars': False}
        return []


class FakeDocument:
    def __init__(self, page_count: int) -> None:
        self.metadata: dict[str, object] = {}
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


def test_pdf_adapter_extracts_bounded_metadata_link_and_image_features(tmp_path: Path) -> None:
    from PIL import Image
    from reportlab.pdfgen import canvas

    image_path = tmp_path / "stamp.png"
    Image.new("RGB", (8, 8), "red").save(image_path)
    source = tmp_path / "features.pdf"
    document = canvas.Canvas(str(source), invariant=1)
    document.setAuthor("Private PDF Author")
    document.drawString(72, 720, "Signature")
    document.drawImage(str(image_path), 72, 680, width=20, height=20)
    document.linkURL("https://example.test/private", (72, 710, 140, 730))
    document.save()

    snapshot = PdfAdapter().load(source, render=False, workdir=tmp_path / "work")

    facts = snapshot.metadata["document_features"]
    assert {item["kind"] for item in facts} >= {
        "metadata",
        "external_link",
        "embedded_image",
    }
    serialized = json.dumps(facts, sort_keys=True)
    assert "Private PDF Author" not in serialized
    assert "https://example.test/private" not in serialized


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


class CloseTracking:
    def __init__(self) -> None:
        self.close_error: RuntimeError | None = None
        self.close_order: list[str] | None = None
        self.close_name = ''
        self.close_calls = 0
        self.closed = False

    def record_close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_order is not None:
            self.close_order.append(self.close_name)
        if self.close_error is not None:
            raise self.close_error


class RenderImage(CloseTracking):
    def __init__(self, *, convert_error: RuntimeError | None = None) -> None:
        super().__init__()
        self.convert_error = convert_error
        self.save_error: RuntimeError | None = None
        self.converted: RenderImage | None = None

    def convert(self, mode: str) -> 'RenderImage':
        assert mode == 'RGB'
        if self.convert_error is not None:
            raise self.convert_error
        assert self.converted is not None
        return self.converted

    def save(self, _: Path) -> None:
        if self.save_error is not None:
            raise self.save_error

    def close(self) -> None:
        self.record_close()


class RenderBitmap(CloseTracking):
    def __init__(self, image: RenderImage) -> None:
        super().__init__()
        self.image = image

    def to_pil(self) -> RenderImage:
        return self.image

    def close(self) -> None:
        self.record_close()


class RenderPage(CloseTracking):
    def __init__(self, bitmap: RenderBitmap) -> None:
        super().__init__()
        self.bitmap = bitmap

    def render(self, *, scale: float) -> RenderBitmap:
        assert scale == 2.0
        return self.bitmap

    def close(self) -> None:
        self.record_close()


class RenderDocument(CloseTracking):
    def __init__(self, page: RenderPage) -> None:
        super().__init__()
        self.page = page

    def __getitem__(self, index: int) -> RenderPage:
        assert index == 0
        return self.page

    def close(self) -> None:
        self.record_close()


def render_snapshot() -> PageSnapshot:
    return PageSnapshot(index=0, width=612, height=792, text='', normalized_text='')


def test_pdf_render_closes_bitmap_and_pil_images_after_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_image = RenderImage()
    converted_image = RenderImage()
    source_image.converted = converted_image
    bitmap = RenderBitmap(source_image)
    page = RenderPage(bitmap)
    document = RenderDocument(page)
    monkeypatch.setattr(pdf_module.pdfium, 'PdfDocument', lambda _: document)

    PdfAdapter._render_pages(tmp_path / 'source.pdf', [render_snapshot()], tmp_path / 'work')

    assert bitmap.closed
    assert source_image.closed
    assert converted_image.closed
    assert page.closed
    assert document.closed


@pytest.mark.parametrize('failure_stage', ['convert', 'save'])
def test_pdf_render_closes_bitmap_and_images_when_conversion_or_save_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    expected_error = RuntimeError(f'{failure_stage} failed')
    source_image = RenderImage(convert_error=expected_error if failure_stage == 'convert' else None)
    converted_image = RenderImage()
    converted_image.save_error = expected_error if failure_stage == 'save' else None
    source_image.converted = converted_image
    bitmap = RenderBitmap(source_image)
    page = RenderPage(bitmap)
    document = RenderDocument(page)
    monkeypatch.setattr(pdf_module.pdfium, 'PdfDocument', lambda _: document)

    with pytest.raises(RuntimeError) as error:
        PdfAdapter._render_pages(
            tmp_path / 'source.pdf', [render_snapshot()], tmp_path / 'work'
        )

    assert error.value is expected_error
    assert bitmap.closed
    assert source_image.closed
    assert converted_image.closed is (failure_stage == 'save')
    assert page.closed
    assert document.closed


def test_pdf_render_preserves_save_error_when_image_close_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_error = RuntimeError('save failed')
    source_image = RenderImage()
    converted_image = RenderImage()
    converted_image.save_error = save_error
    converted_image.close_error = RuntimeError('image close failed')
    source_image.converted = converted_image
    bitmap = RenderBitmap(source_image)
    page = RenderPage(bitmap)
    document = RenderDocument(page)
    monkeypatch.setattr(pdf_module.pdfium, 'PdfDocument', lambda _: document)

    with pytest.raises(RuntimeError) as error:
        PdfAdapter._render_pages(
            tmp_path / 'source.pdf', [render_snapshot()], tmp_path / 'work'
        )

    assert error.value is save_error
    assert converted_image.closed
    assert source_image.closed
    assert bitmap.closed
    assert page.closed
    assert document.closed


def test_pdf_render_preserves_convert_error_when_source_and_bitmap_close_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    convert_error = RuntimeError('convert failed')
    source_image = RenderImage(convert_error=convert_error)
    source_image.close_error = RuntimeError('source close failed')
    bitmap = RenderBitmap(source_image)
    bitmap.close_error = RuntimeError('bitmap close failed')
    page = RenderPage(bitmap)
    document = RenderDocument(page)
    monkeypatch.setattr(pdf_module.pdfium, 'PdfDocument', lambda _: document)

    with pytest.raises(RuntimeError) as error:
        PdfAdapter._render_pages(
            tmp_path / 'source.pdf', [render_snapshot()], tmp_path / 'work'
        )

    assert error.value is convert_error
    assert source_image.closed
    assert bitmap.closed
    assert page.closed
    assert document.closed


def test_pdf_render_propagates_cleanup_error_when_rendering_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    converted_error = RuntimeError('converted close failed')
    source_image = RenderImage()
    converted_image = RenderImage()
    converted_image.close_error = converted_error
    source_image.close_error = RuntimeError('source close failed')
    source_image.converted = converted_image
    bitmap = RenderBitmap(source_image)
    page = RenderPage(bitmap)
    document = RenderDocument(page)
    close_order: list[str] = []
    resources = [
        ('converted', converted_image),
        ('source', source_image),
        ('bitmap', bitmap),
        ('page', page),
        ('document', document),
    ]
    for name, resource in resources:
        resource.close_name = name
        resource.close_order = close_order
    monkeypatch.setattr(pdf_module.pdfium, 'PdfDocument', lambda _: document)

    with pytest.raises(RuntimeError) as error:
        PdfAdapter._render_pages(
            tmp_path / 'source.pdf', [render_snapshot()], tmp_path / 'work'
        )

    assert error.value is converted_error
    assert close_order == ['converted', 'source', 'bitmap', 'page', 'document']
    assert [resource.close_calls for _, resource in resources] == [1, 1, 1, 1, 1]
