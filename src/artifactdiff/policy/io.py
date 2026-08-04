"""Bounded, nondisclosing YAML and JSON policy file IO."""

import json
import re
import tempfile
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.events import MappingEndEvent, MappingStartEvent, SequenceEndEvent, SequenceStartEvent
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver
from yaml.tokens import AliasToken, AnchorToken, TagToken

from artifactdiff.errors import PolicyValidationError
from artifactdiff.policy.canonical import _canonical_payload, canonical_policy_bytes
from artifactdiff.policy.models import ContractPolicy

MAX_POLICY_BYTES = 1_048_576
MAX_POLICY_NESTING = 64
SUPPORTED_POLICY_SUFFIXES = frozenset({".json", ".yaml", ".yml"})


class _UnsafePolicyInput(ValueError):
    pass


def _normalized_mapping_key(key: str) -> str:
    return unicodedata.normalize("NFC", key)


def _mapping_from_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    normalized_keys: set[str] = set()
    for key, value in pairs:
        if not isinstance(key, str):
            raise _UnsafePolicyInput
        normalized_key = _normalized_mapping_key(key)
        if normalized_key in normalized_keys:
            raise _UnsafePolicyInput
        normalized_keys.add(normalized_key)
        result[key] = value
    return result


class _PolicyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


_YAML_BOOLEAN_TAG = "tag:yaml.org,2002:bool"
_PolicyLoader.yaml_implicit_resolvers = {
    initial: [(tag, pattern) for tag, pattern in resolvers if tag != _YAML_BOOLEAN_TAG]
    for initial, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_PolicyLoader.add_implicit_resolver(
    _YAML_BOOLEAN_TAG,
    re.compile(r"^(?:true|false)$"),
    list("tf"),
)


def _construct_mapping(
    loader: _PolicyLoader, node: MappingNode, deep: bool = False
) -> dict[str, Any]:
    if not isinstance(node, MappingNode):
        raise _UnsafePolicyInput
    if any(key_node.tag == "tag:yaml.org,2002:merge" for key_node, _ in node.value):
        raise _UnsafePolicyInput
    loader.flatten_mapping(node)
    pairs: list[tuple[str, Any]] = []
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise _UnsafePolicyInput
        value = loader.construct_object(value_node, deep=deep)
        pairs.append((key, value))
    return _mapping_from_pairs(pairs)


_PolicyLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _load_json(text: str) -> object:
    _validate_json_nesting(text)

    def reject_nonstandard_number(_value: str) -> object:
        raise _UnsafePolicyInput

    return json.loads(
        text,
        object_pairs_hook=_mapping_from_pairs,
        parse_constant=reject_nonstandard_number,
    )


def _validate_json_nesting(text: str) -> None:
    """Reject JSON deeper than 64 collections without recursive parsing."""
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_POLICY_NESTING:
                raise _UnsafePolicyInput
        elif character in "]}" and depth:
            depth -= 1


def _validate_yaml_nesting(text: str) -> None:
    """Reject YAML deeper than 64 collections using parser events."""
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
            depth += 1
            if depth > MAX_POLICY_NESTING:
                raise _UnsafePolicyInput
        elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
            depth -= 1


def _load_yaml(text: str) -> object:
    for token in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(token, (AliasToken, AnchorToken, TagToken)):
            raise _UnsafePolicyInput
    _validate_yaml_nesting(text)
    loader = _PolicyLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _validated_payload(text: str, suffix: str) -> ContractPolicy:
    try:
        payload = _load_json(text) if suffix == ".json" else _load_yaml(text)
        if not isinstance(payload, dict):
            raise _UnsafePolicyInput
        return ContractPolicy.model_validate(payload)
    except (
        ValidationError,
        json.JSONDecodeError,
        yaml.YAMLError,
        _UnsafePolicyInput,
        RecursionError,
        OverflowError,
    ):
        raise PolicyValidationError("invalid policy file") from None


def load_policy(path: Path) -> ContractPolicy:
    """Load one strict policy from a bounded UTF-8 JSON or YAML file."""
    suffix = path.suffix.casefold()
    if suffix not in SUPPORTED_POLICY_SUFFIXES:
        raise PolicyValidationError("unsupported policy format")
    try:
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyValidationError("policy file exceeds 1 MiB limit")
        raw = path.read_bytes()
    except PolicyValidationError:
        raise
    except OSError:
        raise PolicyValidationError("unable to read policy file") from None
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyValidationError("policy file exceeds 1 MiB limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PolicyValidationError("invalid policy file") from None
    return _validated_payload(text, suffix)


def write_policy(policy: ContractPolicy, path: Path) -> Path:
    """Atomically write deterministic policy JSON or safe YAML."""
    suffix = path.suffix.casefold()
    if suffix not in SUPPORTED_POLICY_SUFFIXES:
        raise PolicyValidationError("unsupported policy format")

    payload = _canonical_payload(policy)
    if suffix == ".json":
        contents = canonical_policy_bytes(policy)
    else:
        contents = yaml.safe_dump(
            payload,
            allow_unicode=True,
            sort_keys=True,
        ).encode("utf-8")

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(contents)
            stream.flush()
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path
