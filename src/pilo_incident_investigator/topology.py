"""Strict PILO topology loading and resource authorization."""

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class TopologyError(ValueError):
    """Raised when topology configuration is malformed or out of scope."""


class TopologyDenied(PermissionError):
    """Raised when a resource is outside the topology allowlist."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys at every mapping level."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise TopologyError("YAML mapping key must be hashable") from error
            if duplicate:
                raise TopologyError("duplicate YAML key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True, slots=True)
class ServiceTopology:
    key: str
    ecs_cluster: str
    ecs_service: str
    log_groups: tuple[str, ...]
    target_groups: tuple[str, ...]
    rds_instances: tuple[str, ...]
    queues: tuple[str, ...]
    github_repository: str


@dataclass(frozen=True, slots=True)
class Topology:
    environment: str
    region: str
    services: tuple[ServiceTopology, ...]
    alarm_mappings: tuple[tuple[str, tuple[str, ...]], ...]
    _allowed_resources: tuple[tuple[str, frozenset[str]], ...] = field(repr=False)

    @classmethod
    def load(cls, text: str) -> "Topology":
        try:
            raw = yaml.load(text, Loader=_UniqueKeyLoader)
        except yaml.YAMLError as error:
            raise TopologyError("invalid YAML") from error
        if not isinstance(raw, dict):
            raise TopologyError("topology must be a mapping")
        expected_fields = {"version", "environment", "region", "services", "alarms"}
        unknown_fields = set(raw) - expected_fields
        if unknown_fields:
            raise TopologyError("topology contains unknown fields")
        if raw.get("version") != 1:
            raise TopologyError("topology version must be 1")
        if raw.get("environment") != "dev":
            raise TopologyError("environment must be dev")
        if raw.get("region") != "ap-northeast-2":
            raise TopologyError("region must be ap-northeast-2")

        service_rows = raw.get("services")
        if not isinstance(service_rows, list) or len(service_rows) != 8:
            raise TopologyError("topology must contain exactly 8 services")
        services = tuple(_parse_service(row) for row in service_rows)
        service_keys = [service.key for service in services]
        if len(service_keys) != len(set(service_keys)):
            raise TopologyError("service keys must be unique")
        _reject_duplicate_service_resources(services)

        alarms = raw.get("alarms")
        if not isinstance(alarms, dict):
            raise TopologyError("alarms must be a mapping")
        alarm_mappings = tuple(
            (_require_string(alarm_arn, "alarm ARN"), _require_string_tuple(keys, "alarm services"))
            for alarm_arn, keys in alarms.items()
        )
        known_services = set(service_keys)
        for _, mapped_keys in alarm_mappings:
            if not mapped_keys:
                raise TopologyError("alarm must map to at least one service")
            unknown = set(mapped_keys) - known_services
            if unknown:
                raise TopologyError("alarm references unknown services")

        allowed_resources = _build_allowed_resources(services, alarm_mappings)
        return cls(
            environment="dev",
            region="ap-northeast-2",
            services=services,
            alarm_mappings=alarm_mappings,
            _allowed_resources=tuple(allowed_resources.items()),
        )

    def resolve_alarm(self, alarm_arn: str) -> tuple[ServiceTopology, ...]:
        mappings = dict(self.alarm_mappings)
        mapped_keys = set(mappings.get(alarm_arn, ()))
        return tuple(service for service in self.services if service.key in mapped_keys)

    def require_allowed(self, resource_type: str, resource_id: str) -> None:
        allowed = dict(self._allowed_resources).get(resource_type, frozenset())
        if resource_id not in allowed:
            raise TopologyDenied(f"{resource_type} is not allowlisted")


def _parse_service(raw: Any) -> ServiceTopology:
    if not isinstance(raw, dict):
        raise TopologyError("each service must be a mapping")
    expected_fields = {
        "key",
        "ecs_cluster",
        "ecs_service",
        "log_groups",
        "target_groups",
        "rds_instances",
        "queues",
        "github_repository",
    }
    if set(raw) - expected_fields:
        raise TopologyError("service contains unknown fields")
    return ServiceTopology(
        key=_require_string(raw.get("key"), "service key"),
        ecs_cluster=_require_string(raw.get("ecs_cluster"), "ecs_cluster"),
        ecs_service=_require_string(raw.get("ecs_service"), "ecs_service"),
        log_groups=_require_string_tuple(raw.get("log_groups"), "log_groups"),
        target_groups=_require_string_tuple(raw.get("target_groups"), "target_groups"),
        rds_instances=_require_string_tuple(raw.get("rds_instances"), "rds_instances"),
        queues=_require_string_tuple(raw.get("queues"), "queues"),
        github_repository=_require_string(raw.get("github_repository"), "github_repository"),
    )


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TopologyError(f"{field_name} must be a non-empty string")
    return value


def _require_string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TopologyError(f"{field_name} must be a list")
    values = tuple(_require_string(item, field_name) for item in value)
    if len(values) != len(set(values)):
        raise TopologyError(f"{field_name} must not contain duplicates")
    return values


def _build_allowed_resources(
    services: tuple[ServiceTopology, ...],
    alarm_mappings: tuple[tuple[str, tuple[str, ...]], ...],
) -> dict[str, frozenset[str]]:
    return {
        "alarm": frozenset(alarm_arn for alarm_arn, _ in alarm_mappings),
        "ecs_cluster": frozenset(service.ecs_cluster for service in services),
        "ecs_service": frozenset(service.ecs_service for service in services),
        "log_group": frozenset(item for service in services for item in service.log_groups),
        "target_group": frozenset(item for service in services for item in service.target_groups),
        "rds_instance": frozenset(item for service in services for item in service.rds_instances),
        "queue": frozenset(item for service in services for item in service.queues),
        "github_repository": frozenset(service.github_repository for service in services),
    }


def _reject_duplicate_service_resources(services: tuple[ServiceTopology, ...]) -> None:
    resource_groups = {
        "ecs_service": [service.ecs_service for service in services],
        "log_group": [item for service in services for item in service.log_groups],
        "target_group": [item for service in services for item in service.target_groups],
        "rds_instance": [item for service in services for item in service.rds_instances],
        "queue": [item for service in services for item in service.queues],
        "github_repository": [service.github_repository for service in services],
    }
    for resource_type, resources in resource_groups.items():
        if len(resources) != len(set(resources)):
            raise TopologyError(f"duplicate resource identifier for {resource_type}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a PILO topology file")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser(
        "validate", help="validate topology without printing it"
    )
    validate_parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        topology = Topology.load(args.path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, TopologyError):
        print("invalid topology", file=sys.stderr)
        return 2
    print(f"valid topology: {len(topology.services)} services")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
