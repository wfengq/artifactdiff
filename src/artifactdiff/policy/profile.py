"""Contract-safe profile constants and security constraints."""

from artifactdiff.errors import PolicyValidationError
from artifactdiff.policy.models import ContractPolicy

CONTRACT_SAFE_PROFILE_VERSION = "1.0"


def validate_contract_safe_plugins(policy: ContractPolicy) -> None:
    """Reject plugin capabilities unavailable to the local contract-safe core."""
    if any(
        requirement.allow_network or requirement.allow_model
        for requirement in policy.required_plugins.values()
    ):
        raise PolicyValidationError("contract-safe does not permit requested plugin capabilities")
