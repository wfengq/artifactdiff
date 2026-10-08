# Document-Level Pure-Edit Verdict ("D+") Design

Date: 2026-10-08
Status: draft for review
Builds on: `2026-08-04-artifactdiff-contract-verification-gate-design.md`,
`2026-08-11-exact-occurrence-alignment-design.md` (§9 shortcut addendum),
`2026-10-08-evaluation-harness-design.md`

## 1. Problem

The verdict is decided per clause. Clause segmentation, pairing and heading detection all feed
into whether a change counts as explained. On CUAD v1, 100 contracts × DOCX + PDF, after the
clause-level shortcut:

- 0 false passes, and 97 of 130 authorized-only edits accepted.
- The remaining false blocks come from the clause model, not from real extra changes:
  - pairing failures, where the first sentence is used as the heading;
  - value-based protected-entity ambiguity, where the same value appears twice in a clause, e.g.
    `ninety (90) days` next to `90 days`;
  - a few cases still being investigated.
- Each fix so far has been a patch on the clause model. More of them would overfit the benchmark.

Separately, change detection has had normalization blind spots in the past (casefolding, fixed
in this branch). A second, independent check would stop that class of bug from becoming a false
pass.

## 2. Goal

Two outcomes, without rewriting the verification engine or changing any external format:

1. **Pure authorized edits pass regardless of clause structure.** If the candidate is exactly the
   baseline with the declared replacements applied, it passes. "Exactly" means apart from
   whitespace, and it covers the whole document body plus protected regions and features.
2. **The document level vetoes clause-level PASS.** If the document-level comparison shows any
   unexplained difference, the verdict can never be PASS.

Non-goals:

- Changing how `allow` edits are evaluated.
- Changing bundle, verdict or facts schemas, the review desk or the reports.
- Visual-evidence logic.

## 3. Definitions

**Document text.** `"\n".join(clause.text for clause in document.clauses)`. A probe of the
analyzer confirmed that every body block lands in exactly one clause, including the preface
before the first heading, tables and signature paragraphs. Headers and footers live only in
`protected_regions` and are compared by fingerprint (§4, condition 5).

**Authorized document text.** The baseline document text with each expected rule's anchored
`before` spans replaced by `after`. Spans come from the existing expected phase: the baseline
selector resolves to a clause, and `_find_spans` returns the occurrences inside it. Each span is
then shifted by the offset of its clause in the joined document text.

**Comparison.** `comparison_text` (NFC plus whitespace collapse; case-sensitive, added in this
branch) is applied to both the authorized document text and the candidate document text.

## 4. The pure-edit condition

`document_pure` is true only when all of the following hold:

1. **Policy shape.** The policy has at least one expected rule. Every expected rule's baseline
   selector resolves to exactly one clause, and its `before` occurs exactly `occurrences` times
   in that clause (the existing `counted` conditions on the baseline side).
2. **Spans.** No two declared spans overlap in the baseline document.
3. **Unambiguous positions.** Build the authorized document text and record the region where
   each `after` value was inserted. Search the authorized text for `after` at every start index,
   overlapping matches included. Every occurrence that overlaps an inserted region must coincide
   with that region exactly. Also, no occurrence of `before` may overlap an inserted region,
   which means the replacement does not recreate the original text. If either check fails, the
   document is not pure.

   Example: in `babbbaa`, replacing `baa` with `bbb` gives `babbbbb`. There `bbb` is also found
   at index 2, which overlaps the inserted region at 4–6 without coinciding with it, so the
   document is not pure. The clause engine (DP) then rejects it, as it does today. This keeps
   the occurrence-identity invariant of the 2026-08-11 design at the document level. The
   reviewer decided on 2026-10-08 that position-ambiguous replacements must not pass.
4. **Body text.** `comparison_text(authorized) == comparison_text(candidate document text)`.
5. **Protected regions.** The multiset of protected-region fingerprints is identical on both
   sides. Region fingerprints are now case-sensitive.
6. **Features.** The multiset of document-feature fingerprints is identical on both sides:
   comments, tracked revisions, hidden text and links.

When `document_pure` holds, the candidate is exactly what the policy authorizes and nothing
else. The only freedom left is whitespace.

## 5. Verdict integration (`verification/rules.py`)

`evaluate_contract` computes `document_pure` once, after the integrity phase.

**When `document_pure` is true:**

- Each expected rule is treated as applied and exact: one PASS finding per rule, with the same
  rule ID as today. The clause-level DP and pairing are not consulted for authorization.
- `contract-safe.unexplained-clause`, `contract-safe.unresolved-clause` and
  `contract-safe.protected.*` entity findings are not emitted. By condition 4, every body change
  lies inside a declared span, and the existing semantics already authorize entity changes
  inside exact declared spans.
- Region, feature, metadata and visual rules run unchanged. The visual "explained envelope"
  still comes from the expected rules' clause evidence, exactly as today (§8).

**When `document_pure` is false**, the existing clause engine runs unchanged, and then the veto
applies:

- If the clause engine's outcome would be PASS but the document-level comparison found a
  residual difference, the verdict gets a nonapprovable FAIL finding
  `contract-safe.document.residual`. A residual difference means body text not explained by the
  declared replacements, or a difference in regions or features.
- Today, legitimate residual differences only come from `allow` rules, and those already yield
  REVIEW, not PASS. So the veto should never fire on correct inputs; the full test suite checks
  this.

## 6. Why this is sound

- **Pure path.** The candidate's body text equals the authorized text up to whitespace, and the
  protected regions and features are identical. Any change the policy did not declare would
  break one of these three equalities.
- **Occurrence ambiguity.** Even when the final text matches, the gate still requires that each
  declared `after` value can be read only at the position where it was inserted (condition 3).
  This mirrors the clause-level invariant: every pure match accepted here is one the DP would
  also accept. Position-ambiguous cases, such as `babbbaa`, fall back to the clause engine.
- **Veto path.** It can only turn PASS into FAIL, never the reverse.

## 7. Testing

**Unit tests** in `tests/unit/verification/test_rules.py`, each seen failing first:

- A pure edit in a clause that pairs as removed + added (its heading contains the edit) passes,
  even with the label-pairing pass disabled.
- A pure edit of a value that appears twice in the clause (`ninety (90) days` / `90 days`)
  passes.
- A pure edit plus one changed character anywhere else in the body FAILs: it is not pure, and
  the clause engine already fails it.
- A pure edit plus a case change in a header FAILs on the region rule.
- A pure edit plus an added comment goes to REVIEW or FAIL as today.
- The veto: a constructed facts or clause-engine blind spot where the clause engine would PASS
  but a residual exists ends in FAIL with `contract-safe.document.residual`. One way to build it
  is a candidate clause whose text differs while the facts list no clause change.
- Whitespace-only differences across the whole document still pass.
- Position ambiguity: `babbbaa` with `baa → bbb` as the only change is not pure and still
  FAILs.
- A property test checks that whenever the document-level pure condition holds for a
  single-clause document, the clause-level DP proof also succeeds. It reuses the generator from
  `test_occurrence_alignment.py`.

**Existing suite:** all of it passes unchanged, which shows the veto never fires on today's
correct inputs.

**Evaluation:**

- CUAD 100-contract run before and after, plus a held-out run on 100 contracts the clause fixes
  were not tuned on (`--seed 1`).
- Success means: false passes stay at 0 in both runs, and authorized-edit acceptance rises
  toward 100% for pure edits.

## 8. Limits and follow-ups

- `allow` edits and multi-rule clauses with additional edits still rely on the clause engine.
  If the evaluation shows that this scenario dominates the remaining false blocks, the next step
  is the full document-level engine (option B), which reuses §3–§4.
- Cross-format comparison (DOCX baseline against a rendered PDF candidate) can produce
  extraction-level text differences such as ligatures or hyphenation. Those make a document not
  pure, so it falls back to the clause engine. That is safe, but no faster than today.
- The visual envelope for pure edits is unchanged. A follow-up could narrow it to the declared
  spans.
