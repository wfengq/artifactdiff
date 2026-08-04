"""Machine- and human-readable report writers."""

from artifactdiff.reporting.html import write_html
from artifactdiff.reporting.json import write_json

__all__ = ["write_html", "write_json"]
