"""Domain exceptions raised by ArtifactDiff."""


class ArtifactDiffError(Exception):
    """Base exception for expected ArtifactDiff failures."""


class InputValidationError(ArtifactDiffError):
    """Raised when a provided input is invalid."""


class PolicyValidationError(InputValidationError):
    """Raised when policy input cannot be validated safely."""


class UnsupportedFormatError(InputValidationError):
    """Raised when a source file format is unsupported."""


class ResourceLimitError(ArtifactDiffError):
    """Raised when processing would exceed a configured resource limit."""


class RenderUnavailableError(ArtifactDiffError):
    """Raised when a requested rendering capability is unavailable."""


class SignatureError(ArtifactDiffError):
    """Raised when signing material or trust validation is invalid."""


class PathSafetyError(ArtifactDiffError):
    """Raised when a path escapes its configured trust boundary."""


class SessionError(ArtifactDiffError):
    """Raised when a verified edit session cannot be safely created or loaded."""


class BundleError(ArtifactDiffError):
    """Raised when a Review Bundle cannot be safely created or verified."""


class ApprovalError(ArtifactDiffError):
    """Raised when a finding decision cannot be safely appended or verified."""


class EvidenceError(ArtifactDiffError):
    """Raised when evidence cannot be collected or archived safely."""


class EncryptionUnavailableError(EvidenceError):
    """Raised when the configured age encryption provider is unavailable."""
