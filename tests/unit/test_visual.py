from pathlib import Path

from PIL import Image, ImageDraw

from artifactdiff.visual import compare_images


def test_compare_images_reports_unchanged(tmp_path: Path) -> None:
    source = Image.new("RGB", (128, 128), "white")
    before = tmp_path / "before.png"
    after = tmp_path / "after.png"
    source.save(before)
    source.save(after)

    change, assets = compare_images(before, after, output_dir=tmp_path / "diff")

    assert change.changed_pixel_ratio == 0.0
    assert change.regions == []
    assert assets.heatmap_image.is_file()


def test_compare_images_finds_local_region(tmp_path: Path) -> None:
    original = Image.new("RGB", (128, 128), "white")
    changed = original.copy()
    ImageDraw.Draw(changed).rectangle((40, 40, 70, 70), fill="black")
    before = tmp_path / "before.png"
    after = tmp_path / "after.png"
    original.save(before)
    changed.save(after)

    result, _ = compare_images(before, after, output_dir=tmp_path / "diff", tile_size=16)

    assert result.changed_pixel_ratio == 961 / 16384
    assert [region.model_dump() for region in result.regions] == [
        {"x0": 32.0, "y0": 32.0, "x1": 80.0, "y1": 80.0}
    ]


def test_compare_images_pads_at_top_left_without_stretching(tmp_path: Path) -> None:
    before = Image.new("RGB", (2, 3), (32, 32, 32))
    after = Image.new("RGB", (4, 2), "white")
    before_path = tmp_path / "narrow.png"
    after_path = tmp_path / "wide.png"
    before.save(before_path)
    after.save(after_path)

    result, assets = compare_images(before_path, after_path, output_dir=tmp_path / "diff")

    assert result.changed_pixel_ratio == 10 / 12
    with Image.open(assets.before_image) as padded_before:
        assert padded_before.mode == "RGB"
        assert padded_before.size == (4, 3)
        assert padded_before.getpixel((1, 2)) == (32, 32, 32)
        assert padded_before.getpixel((2, 2)) == (255, 255, 255)
    with Image.open(assets.after_image) as padded_after:
        assert padded_after.mode == "RGB"
        assert padded_after.size == (4, 3)
        assert padded_after.getpixel((3, 1)) == (255, 255, 255)


def test_compare_images_clamps_threshold_and_uses_strict_boundary(tmp_path: Path) -> None:
    before = Image.new("RGB", (3, 1), "black")
    after = Image.new("RGB", (3, 1), "black")
    after.putdata([(16, 16, 16), (17, 17, 17), (255, 255, 255)])
    before_path = tmp_path / "before.png"
    after_path = tmp_path / "after.png"
    before.save(before_path)
    after.save(after_path)

    at_boundary, _ = compare_images(
        before_path, after_path, output_dir=tmp_path / "boundary", threshold=16
    )
    below_range, _ = compare_images(
        before_path, after_path, output_dir=tmp_path / "below", threshold=-20
    )
    above_range, _ = compare_images(
        before_path, after_path, output_dir=tmp_path / "above", threshold=999
    )

    assert at_boundary.changed_pixel_ratio == 2 / 3
    assert below_range.changed_pixel_ratio == 1.0
    assert above_range.changed_pixel_ratio == 0.0


def test_compare_images_coalesces_tiles_with_stable_region_order(tmp_path: Path) -> None:
    before = Image.new("RGB", (40, 24), "white")
    after = before.copy()
    after.putpixel((1, 1), (0, 0, 0))
    after.putpixel((9, 1), (0, 0, 0))
    after.putpixel((1, 9), (0, 0, 0))
    after.putpixel((9, 9), (0, 0, 0))
    after.putpixel((33, 1), (0, 0, 0))
    before_path = tmp_path / "before.png"
    after_path = tmp_path / "after.png"
    before.save(before_path)
    after.save(after_path)

    result, _ = compare_images(before_path, after_path, output_dir=tmp_path / "diff", tile_size=1)

    assert [region.model_dump() for region in result.regions] == [
        {"x0": 0.0, "y0": 0.0, "x1": 16.0, "y1": 16.0},
        {"x0": 32.0, "y0": 0.0, "x1": 40.0, "y1": 8.0},
    ]


def test_compare_images_writes_named_rgb_assets_and_exact_heatmap(tmp_path: Path) -> None:
    before = Image.new("RGBA", (2, 1), "white")
    after = Image.new("RGBA", (2, 1), "white")
    after.putpixel((1, 0), (0, 0, 0, 255))
    before_path = tmp_path / "before input.png"
    after_path = tmp_path / "after input.png"
    before.save(before_path)
    after.save(after_path)
    output_dir = tmp_path / "nested output" / "page 1"

    _, assets = compare_images(before_path, after_path, output_dir=output_dir)

    assert assets.before_image == output_dir / "before.png"
    assert assets.after_image == output_dir / "after.png"
    assert assets.heatmap_image == output_dir / "heatmap.png"
    for path in (assets.before_image, assets.after_image, assets.heatmap_image):
        with Image.open(path) as image:
            assert image.mode == "RGB"
            assert image.size == (2, 1)
    with Image.open(assets.heatmap_image) as heatmap:
        assert [heatmap.getpixel((0, 0)), heatmap.getpixel((1, 0))] == [
            (255, 255, 255),
            (255, 0, 0),
        ]

    before_path.unlink()
    after_path.unlink()
    assert not before_path.exists()
    assert not after_path.exists()


def test_compare_images_counts_different_page_extents_as_changed(tmp_path: Path) -> None:
    before = tmp_path / "before.png"
    after = tmp_path / "after.png"
    Image.new("RGB", (80, 100), "white").save(before)
    Image.new("RGB", (100, 80), "white").save(after)

    result, assets = compare_images(before, after, output_dir=tmp_path / "diff")

    assert result.changed_pixel_ratio == 0.32
    with Image.open(assets.before_image) as padded_before:
        assert padded_before.size == (100, 100)
    with Image.open(assets.after_image) as padded_after:
        assert padded_after.size == (100, 100)
