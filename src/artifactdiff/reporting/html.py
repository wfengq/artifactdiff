"""Self-contained, deterministic HTML report generation."""

import base64
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from artifactdiff.models import ComparisonResult
from artifactdiff.visual import VisualAssets


def _data_uri(path: Path) -> str:
    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError as error:
        raise ValueError(f"Unable to read visual asset {path}: {error}") from error
    return f"data:image/png;base64,{encoded}"


def write_html(
    result: ComparisonResult,
    visual_assets: dict[str, VisualAssets],
    path: Path,
) -> Path:
    """Write one portable HTML report with inline assets."""
    missing = list(
        dict.fromkeys(
            change.id for change in result.visual_changes if change.id not in visual_assets
        )
    )
    if missing:
        raise ValueError(f"Missing visual assets for: {', '.join(missing)}")

    environment = Environment(
        loader=PackageLoader("artifactdiff", "reporting"),
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
    )
    visuals: dict[str, dict[str, str]] = {}
    for change in result.visual_changes:
        assets = visual_assets[change.id]
        visuals[change.id] = {
            "before": _data_uri(assets.before_image),
            "after": _data_uri(assets.after_image),
            "heatmap": _data_uri(assets.heatmap_image),
        }
    rendered = environment.get_template("template.html").render(result=result, visuals=visuals)

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path
