"""Fail-closed YAML loading and anonymity checks for evaluation fixtures."""

from pathlib import Path
from typing import Any, cast

import yaml
from yaml.tokens import AliasToken, AnchorToken

from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.evaluation.schema import (
    EvalFixture,
    FixtureValidationError,
    assert_anonymous,
)

_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_MAX_NESTING_DEPTH = 64


class _UniqueJsonLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys and keeps timestamps as strings."""

    yaml_implicit_resolvers = {
        key: [(tag, regexp) for tag, regexp in resolvers if tag != _TIMESTAMP_TAG]
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise FixtureValidationError("YAML mapping key must be hashable") from error
            if duplicate:
                raise FixtureValidationError("duplicate YAML key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_fixture(path: Path) -> EvalFixture:
    raw = _load_yaml(path, "fixture")
    if not isinstance(raw, dict):
        raise FixtureValidationError("fixture must be a mapping")
    return EvalFixture.from_dict(cast(dict[str, JsonValue], raw))


def load_manifest(path: Path) -> tuple[EvalFixture, ...]:
    raw_value = _load_yaml(path, "manifest")
    raw = _mapping(raw_value, "manifest")
    _exact_fields(raw, {"version", "fixtures"}, "manifest")
    version = raw["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise FixtureValidationError("manifest version must be 1")
    entries_value = raw["fixtures"]
    if not isinstance(entries_value, list):
        raise FixtureValidationError("manifest.fixtures must be a list")
    entries = [_parse_manifest_entry(item, index) for index, item in enumerate(entries_value)]
    fixture_ids = [entry["fixture_id"] for entry in entries]
    if len(fixture_ids) != len(set(fixture_ids)):
        raise FixtureValidationError("duplicate fixture_id in manifest")
    relative_paths = [entry["path"] for entry in entries]
    if len(relative_paths) != len(set(relative_paths)):
        raise FixtureValidationError("duplicate fixture path in manifest")

    manifest_directory = path.resolve().parent
    fixtures: list[EvalFixture] = []
    for entry in entries:
        fixture_path = _child_path(manifest_directory, entry["path"])
        fixture = load_fixture(fixture_path)
        if (
            fixture.fixture_id != entry["fixture_id"]
            or fixture.scenario != entry["scenario"]
            or fixture.variant != entry["variant"]
        ):
            raise FixtureValidationError("manifest metadata does not match fixture")
        fixtures.append(fixture)
    return tuple(fixtures)


def _load_yaml(path: Path, kind: str) -> object:
    try:
        text = path.read_text(encoding="utf-8")
        _reject_yaml_aliases(text)
        raw = yaml.load(text, Loader=_UniqueJsonLoader)
    except FixtureValidationError:
        raise
    except (OSError, RecursionError, UnicodeError, yaml.YAMLError):
        raise FixtureValidationError(f"{kind} could not be loaded") from None
    json_value = _json_value(raw, kind)
    assert_anonymous(json_value)
    return json_value


def _reject_yaml_aliases(text: str) -> None:
    if any(isinstance(token, AnchorToken | AliasToken) for token in yaml.scan(text)):
        raise FixtureValidationError("YAML aliases and anchors are not allowed")


def _json_value(
    value: object,
    path: str,
    *,
    depth: int = 0,
    active_containers: set[int] | None = None,
) -> JsonValue:
    if depth > _MAX_NESTING_DEPTH:
        raise FixtureValidationError("maximum fixture nesting depth exceeded")
    if value is None or isinstance(value, bool | int | float | str):
        return value
    active = set() if active_containers is None else active_containers
    if isinstance(value, list):
        marker = id(value)
        if marker in active:
            raise FixtureValidationError("cyclic fixture structure is not allowed")
        active.add(marker)
        try:
            return [
                _json_value(
                    item,
                    f"{path}[]",
                    depth=depth + 1,
                    active_containers=active,
                )
                for item in value
            ]
        finally:
            active.remove(marker)
    if isinstance(value, dict):
        marker = id(value)
        if marker in active:
            raise FixtureValidationError("cyclic fixture structure is not allowed")
        active.add(marker)
        result: dict[str, JsonValue] = {}
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise FixtureValidationError(f"{path} must use string keys")
                result[key] = _json_value(
                    item,
                    f"{path}.{key}",
                    depth=depth + 1,
                    active_containers=active,
                )
            return result
        finally:
            active.remove(marker)
    raise FixtureValidationError(f"{path} must contain only JSON values")


def _mapping(value: object, path: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise FixtureValidationError(f"{path} must be a mapping")
    return cast(dict[str, JsonValue], value)


def _exact_fields(raw: dict[str, JsonValue], expected: set[str], path: str) -> None:
    if set(raw) - expected:
        raise FixtureValidationError(f"{path} contains unknown fields")
    if expected - set(raw):
        raise FixtureValidationError(f"{path} is missing required fields")


def _parse_manifest_entry(value: JsonValue, index: int) -> dict[str, str]:
    path = f"manifest.fixtures[{index}]"
    raw = _mapping(value, path)
    _exact_fields(raw, {"fixture_id", "path", "scenario", "variant"}, path)
    result: dict[str, str] = {}
    for field in ("fixture_id", "path", "scenario", "variant"):
        item = raw[field]
        if not isinstance(item, str) or not item.strip():
            raise FixtureValidationError(f"{path}.{field} must be a non-empty string")
        result[field] = item
    if result["variant"] not in {"complete", "noisy", "partial", "unknown", "composite"}:
        raise FixtureValidationError("unknown fixture variant")
    return result


def _child_path(parent: Path, relative_text: str) -> Path:
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise FixtureValidationError("fixture path must be a relative child path")
    candidate = (parent / relative).resolve()
    if not candidate.is_relative_to(parent):
        raise FixtureValidationError("fixture path must be a relative child path")
    return candidate


__all__ = ["assert_anonymous", "load_fixture", "load_manifest"]
