# ArtifactDiff Contract CJK test font provenance

`ArtifactDiffContractCJK-Regular.ttf` is a test-only glyph subset of Noto Sans SC,
licensed under the SIL Open Font License 1.1 in `OFL.txt`.

- Upstream repository: <https://github.com/google/fonts/tree/main/ofl/notosanssc>
- Pinned upstream commit: `2796410152d4f9524b68ed46e69c1b60f8e0f7c3`
- Source file: `NotoSansSC[wght].ttf`
- Source SHA-256: `a3041811a78c361b1de50f953c805e0244951c21c5bd412f7232ef0d899af0da`
- Subset SHA-256: `4c24d1698a03f8f541bd32f9beb36a6d2933575f680e83a3dc2c04f8bfd83be7`
- Subset size: 72,528 bytes
- Glyph corpus: `contract-glyphs.txt`

Generation used FontTools to instantiate the variable source at weight 400 and subset it to
the checked-in fixture corpus with layout features and Unicode cmaps retained. The derivative's
primary family and PostScript names were changed to `ArtifactDiff Contract CJK` and
`ArtifactDiffContractCJK-Regular`; the upstream reserved font name `Source` is not used.

Equivalent generation commands:

```text
fonttools varLib.instancer NotoSansSC[wght].ttf wght=400 --output NotoSansSC-400.ttf
pyftsubset NotoSansSC-400.ttf --text-file=contract-glyphs.txt \
  --output-file=ArtifactDiffContractCJK-Regular.ttf --layout-features='*' \
  --name-IDs='*' --name-legacy --name-languages='*' --glyph-names --symbol-cmap \
  --legacy-cmap --notdef-glyph --notdef-outline --recommended-glyphs --no-hinting
```

After subsetting, the name-table family, full-name, unique-ID, and PostScript records were
rewritten to the ArtifactDiff names above. FontTools is a generation-only tool and is not a
runtime or test-suite dependency.
