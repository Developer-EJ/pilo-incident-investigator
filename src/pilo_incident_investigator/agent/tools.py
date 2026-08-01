"""Fail-closed registry for the five permitted additional investigation Tools."""

from collections.abc import Mapping
from typing import Protocol

from pilo_incident_investigator.domain import ToolRequest, ToolResult
from pilo_incident_investigator.topology import Topology, TopologyDenied

TOOL_NAMES = frozenset(
    {
        "service_log_search",
        "rds_events",
        "secret_rotation_metadata",
        "sqs_status",
        "github_changed_files",
    }
)

_RESOURCE_TYPES = {
    "service_log_search": "log_group",
    "rds_events": "rds_instance",
    "secret_rotation_metadata": "secret",
    "sqs_status": "queue",
    "github_changed_files": "github_repository",
}


class ToolDenied(PermissionError):
    """Raised before execution when an Agent Tool request violates policy."""


class ToolHandler(Protocol):
    def execute(self, request: ToolRequest) -> ToolResult: ...


class ToolRegistry:
    def __init__(self, handlers: Mapping[str, ToolHandler]) -> None:
        if set(handlers) != TOOL_NAMES:
            raise ValueError("handlers must provide the exact Tool set")
        self._handlers = dict(handlers)

    def execute(
        self,
        request: ToolRequest,
        topology: Topology,
        seen: set[str],
    ) -> ToolResult:
        if request.tool not in TOOL_NAMES:
            raise ToolDenied("unknown Tool")
        if not request.reason.strip():
            raise ToolDenied("Tool selection reason is required")
        key = request.deduplication_key()
        if key in seen:
            raise ToolDenied("duplicate Tool request")
        try:
            topology.require_allowed(_RESOURCE_TYPES[request.tool], request.resource_key)
        except TopologyDenied:
            raise ToolDenied("Tool resource is not allowlisted") from None
        seen.add(key)
        return self._handlers[request.tool].execute(request)
