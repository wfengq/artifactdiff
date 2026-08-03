"""Domain exceptions raised by ArtifactDiff."""


class ArtifactDiffError(Exception):
    """Base exception for expected ArtifactDiff failures."""


class InputValidationError(ArtifactDiffError):
    """Raised when a provided input is invalid."""


class UnsupportedFormatError(InputValidationError):
    """Raised when a source file format is unsupported."""


class ResourceLimitError(ArtifactDiffError):
    """Raised when processing would exceed a configured resource limit."""


class RenderUnavailableError(ArtifactDiffError):
    """Raised when a requested rendering capability is unavailable."""

