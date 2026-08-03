from artifactdiff.models import ComparisonResult


def test_comparison_schema_defaults_to_v1() -> None:
    result = ComparisonResult.model_validate(
        {
            "status": "unchanged",
            "before": {
                "path": "a.pdf",
                "sha256": "a" * 64,
                "format": "pdf",
                "size_bytes": 1,
            },
            "after": {
                "path": "b.pdf",
                "sha256": "a" * 64,
                "format": "pdf",
                "size_bytes": 1,
            },
            "summary": {},
        }
    )

    assert result.schema_version == "1.0"
    assert result.changes == []

