> **Superseded.** This 2026-08-03 MVP note is historical. The current product direction is the contract verification gate (2026-08-04+) and the accepted Golden Path record in `docs/plan-4.5-contract-golden-path.md`.

# ArtifactDiff MVP Design

**Date:** 2026-08-03  
**Status:** Approved for implementation planning

## 1. Product goal

ArtifactDiff is a local-first document comparison tool for humans and AI agents. The MVP compares two PDF or DOCX files, detects deterministic semantic and visual changes, and produces an offline HTML report plus a versioned JSON result. The same comparison engine is exposed through a local CLI and an MCP server.

The MVP succeeds when a user can install the package, compare two supported files with one command, open a useful report without an account or network connection, and invoke the same operation from an MCP-compatible agent.

## 2. Scope

### Included

- PDF and DOCX inputs.
- A cross-platform Python 3.11+ package for Windows, macOS, and Linux.
- A local CLI as the primary human entry point.
- A stdio MCP server as the primary agent entry point.
- Deterministic, offline semantic comparison.
- Native PDF rendering and visual comparison.
- DOCX structural comparison without external software.
- Optional DOCX visual comparison through an installed LibreOffice executable.
- A self-contained HTML report and a sidecar JSON report.
- Configurable CI-style failure when changes are detected.

### Excluded from the MVP

- XLSX and PPTX support.
- OCR or semantic extraction from image-only scans.
- Password input for encrypted documents.
- Cloud services, accounts, telemetry, or network access.
- LLM-generated summaries.
- Document merging, editing, repair, or automatic acceptance of changes.
- A GitHub Action or hosted web application.

## 3. Technology choice

The implementation uses Python because its document-processing ecosystem offers the shortest path to a reliable cross-platform MVP.

- Typer provides the CLI.
- The official Python MCP SDK provides the stdio server.
- pypdfium2 renders PDF pages.
- pdfplumber extracts PDF text and geometry.
- python-docx and targeted OOXML parsing extract DOCX structure.
- Pillow computes and encodes visual differences.
- LibreOffice is an optional external executable used only to render DOCX as PDF.

Rust was rejected for the MVP because native document parsing would dominate the schedule. TypeScript was rejected because the required PDF rendering, DOCX inspection, and pixel processing stack is less cohesive.

## 4. Architecture

The package is divided into independently testable components:

1. **CLI and MCP adapters** validate requests and invoke the application service.
2. **Comparison service** coordinates parsing, alignment, semantic diffing, visual diffing, and report creation.
3. **Format adapters** convert PDF or DOCX input into a common document snapshot.
4. **Page and block aligners** pair related content while recognizing additions and removals.
5. **Semantic differ** creates typed content changes.
6. **Visual differ** renders aligned pages and locates changed image regions.
7. **Report writers** serialize the result as JSON and self-contained HTML.

Format adapters are replaceable. XLSX and PPTX can be added later without changing the CLI, MCP tools, result schema, or report writers.

## 5. Unified document model

A `DocumentSnapshot` records:

- Source path, format, byte size, and SHA-256 hash.
- Document metadata available without interpreting private application state.
- Ordered pages when the source format has stable pages.
- Ordered logical blocks such as headings, paragraphs, tables, headers, and footers.
- Normalized text used for matching, while preserving the original text for reports.
- Optional rendered page images and geometry.

A PDF snapshot contains page text blocks with bounding boxes and rendered pages. A DOCX snapshot contains logical OOXML structure. When LibreOffice is available, a DOCX snapshot also receives rendered pages through the PDF adapter.

## 6. Alignment and semantic comparison

The engine first compares file hashes. Identical hashes produce an unchanged result without parsing or rendering.

For changed files, it computes normalized text fingerprints and uses deterministic sequence alignment to pair pages and logical blocks. This prevents one inserted page or paragraph from making every subsequent item appear modified.

Each semantic change contains:

- `kind`: `added`, `removed`, `modified`, or `moved`.
- `content_type`: page, PDF text block, heading, paragraph, table, header, or footer.
- Stable before and after references.
- Original before and after content.
- A deterministic similarity value.
- `severity`: `info` or `warning`.
- Optional structured details such as heading-level or table-dimension changes.
- Optional visual regions.

Moves are reported only when a high-confidence deterministic match exists. Ambiguous cases are expressed as removal plus addition.

## 7. Visual comparison

PDF pages are rendered at a fixed scale and color mode. Aligned page images are padded to a common canvas without stretching. The visual differ calculates:

- A changed-pixel ratio.
- A difference heatmap.
- Coalesced changed-region rectangles.
- Before and after page images for report presentation.

Minor raster noise is suppressed by a fixed, documented pixel threshold. The threshold is configurable but never chosen by a model.

DOCX visual comparison is optional. If LibreOffice is found, each DOCX is converted to PDF in an isolated temporary directory and processed by the PDF rendering pipeline. If LibreOffice is absent or conversion fails, semantic comparison still succeeds and the result records a warning that visual comparison was unavailable.

## 8. Output schema

The JSON report has a versioned schema beginning with `1.0`. Its top-level fields are:

- `schema_version`
- `status`: `unchanged`, `changed`, or `partial`
- `before` and `after` source descriptors
- `summary` counts and visual-change ratio
- `changes`
- `warnings`
- `artifacts`
- timing and engine-version metadata

The HTML report embeds its styles, scripts, and images so it remains usable when copied to another computer. The JSON report remains a separate machine-readable file for MCP clients and automation.

The CLI returns `0` for a successful comparison. With `--fail-on-change`, it returns `1` when the configured change condition is met. Operational or validation failures return `2`.

## 9. Human report experience

The HTML report contains:

- A summary header with file identity, hashes, formats, change counts, warnings, and visual-change ratio.
- Navigation by changed page or logical structure.
- Filters for change kind and content type.
- Side-by-side, swipe, overlay, and heatmap views for rendered pages.
- A semantic change list linked to the relevant page or block.
- Changed content expanded by default and unchanged content collapsed.
- Keyboard-accessible controls and no dependency on a CDN or remote font.

## 10. CLI and MCP interfaces

The primary CLI command is:

```text
artifactdiff compare BEFORE AFTER --output OUTPUT_DIR
```

Relevant options include `--no-visual`, `--fail-on-change`, configurable thresholds, `--force`, and machine-readable console output.

The MCP server exposes:

### `compare_documents`

Compares two absolute local paths and returns the status, summary, warnings, key changes, and absolute JSON/HTML report paths.

### `inspect_document`

Returns a bounded structural summary of one supported local document so an agent can understand it before making changes.

MCP responses do not embed page images or the complete HTML report in model context.

## 11. Safety and resource controls

- All processing is local and performs no network requests.
- MCP accepts absolute local file paths only.
- Input paths must resolve to regular files with supported extensions.
- The LibreOffice process is started with an argument list and no command shell.
- Each conversion uses an isolated temporary directory and profile.
- Temporary files are removed after report creation, including on handled failures.
- A report output parent is a trust boundary and must be a private directory controlled by the current user. Report publication is atomic and never overwrites an existing final name, but it does not attempt to defend against another same-privilege process that can mutate that directory during or after publication.
- Files larger than 100 MB or documents over 500 pages are rejected unless `--force` is present.
- Encrypted, corrupt, unsupported, or mismatched input formats produce actionable validation errors.

## 12. Error behavior

Fatal errors stop the operation and return exit code `2` or a structured MCP error. Examples include unreadable input, corrupt documents, encrypted PDF files, unsupported formats, and failure to write outputs.

Recoverable degradation produces a `partial` result with warnings. The main example is a valid DOCX semantic comparison for which visual rendering is unavailable.

Error messages identify the affected path, failed stage, and a practical next action without exposing a stack trace by default.

## 13. Testing strategy

### Unit tests

- Text normalization and fingerprints.
- Page and logical-block alignment.
- Semantic change classification.
- Pixel thresholds, ratios, and changed-region coalescing.
- JSON schema serialization and exit-code decisions.

### Format fixtures

Deterministically generated PDF and DOCX pairs exercise unchanged files, paragraph edits, heading changes, table changes, page insertion, page deletion, layout-only changes, and malformed input.

### Integration tests

- CLI argument validation and output paths.
- HTML and JSON generation.
- `--fail-on-change` behavior.
- DOCX operation both with and without LibreOffice.
- Resource limits and temporary-directory cleanup.

### MCP contract tests

- Tool discovery.
- Input validation.
- Structured successful responses.
- Partial-result warnings.
- Bounded, actionable error responses.

### Visual QA

An end-to-end fixture report is opened and inspected to confirm that images render, controls work, changed regions correspond to the source changes, text is legible, and the report remains functional offline.

## 14. Acceptance criteria

The MVP is complete when:

1. Installation succeeds on Python 3.11+ with documented `pipx` and `uvx` commands.
2. One CLI command compares two valid PDFs or DOCX files and produces valid JSON and offline HTML.
3. PDF semantic and visual changes are correctly represented for the fixture suite.
4. DOCX semantic changes work without LibreOffice; visual changes work when LibreOffice is available.
5. Both MCP tools are discoverable and invoke the same application services as the CLI.
6. Identical inputs take the hash fast path.
7. Errors, warnings, resource limits, and exit codes follow this specification.
8. Unit, integration, format, and MCP contract tests pass.
9. The end-to-end report passes visual and offline inspection.

