from artifactdiff.alignment import align_sequences


def test_alignment_does_not_shift_after_insertion() -> None:
    pairs = align_sequences(["a", "b", "c"], ["a", "new", "b", "c"], key=str)

    assert [(pair.before, pair.after) for pair in pairs] == [
        ("a", "a"),
        (None, "new"),
        ("b", "b"),
        ("c", "c"),
    ]


def test_alignment_pairs_similar_replacement() -> None:
    pairs = align_sequences(["quarterly revenue"], ["quarterly net revenue"], key=str)

    assert pairs[0].before == "quarterly revenue"
    assert pairs[0].after == "quarterly net revenue"
    assert pairs[0].similarity > 0.7


def test_alignment_breaks_replacement_ties_by_source_order() -> None:
    pairs = align_sequences(["ab", "ac"], ["ad"], key=str, threshold=0.0)

    assert [(pair.before, pair.after) for pair in pairs] == [
        ("ab", "ad"),
        ("ac", None),
    ]
