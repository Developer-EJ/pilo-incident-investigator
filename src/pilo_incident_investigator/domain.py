"""Immutable domain contracts shared across the incident pipeline."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from math import isfinite

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]


def _require_json_safe(value: object, path: str) -> None:
    if isinstance(value, float) and not isfinite(value):
        raise TypeError(f"{path} must contain only finite JSON numbers")
    if value is None or isinstance(value, bool | int | float | str):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_json_safe(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} must use string keys to remain JSON-safe")
            _require_json_safe(item, f"{path}.{key}")
        return
    raise TypeError(f"{path} must contain only JSON-safe values")


def _require_timezone_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class AlarmEvent:
    event_id: str
    alarm_arn: str
    alarm_name: str
    state_timestamp: datetime
    detail: dict[str, JsonValue]

    def __post_init__(self) -> None:
        _require_timezone_aware(self.state_timestamp, "state_timestamp")
        _require_json_safe(self.detail, "alarm.detail")


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: str
    source: str
    observed_at: datetime
    summary: str
    data: dict[str, JsonValue]

    def __post_init__(self) -> None:
        _require_timezone_aware(self.observed_at, "observed_at")
        _require_json_safe(self.data, "evidence.data")


@dataclass(frozen=True, slots=True)
class CollectorFailure:
    collector: str
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class Snapshot:
    incident_id: str
    evidence: tuple[Evidence, ...]
    failures: tuple[CollectorFailure, ...]

    def __post_init__(self) -> None:
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("duplicate Evidence ID")


@dataclass(frozen=True, slots=True)
class ToolRequest:
    tool: str
    resource_key: str
    parameters: dict[str, JsonValue]
    reason: str

    def __post_init__(self) -> None:
        _require_json_safe(self.parameters, "tool_request.parameters")

    def deduplication_key(self) -> str:
        canonical = json.dumps(
            {
                "parameters": self.parameters,
                "resource_key": self.resource_key,
                "tool": self.tool,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return f"tool-{hashlib.sha256(canonical).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ToolResult:
    request: ToolRequest
    evidence: tuple[Evidence, ...]
    failure: CollectorFailure | None


@dataclass(frozen=True, slots=True)
class SupportedStatement:
    text: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError("supported statement requires at least one Evidence ID")


@dataclass(frozen=True, slots=True)
class Investigation:
    facts: tuple[SupportedStatement, ...]
    directions: tuple[SupportedStatement, ...]
    missing: tuple[str, ...]
    classification: str
    tool_calls: tuple[ToolResult, ...]
    classification_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IncidentBundle:
    incident_id: str
    alarm: AlarmEvent
    snapshot: Snapshot
    investigation: Investigation
    created_at: datetime
    metadata: dict[str, JsonValue]

    def __post_init__(self) -> None:
        if self.snapshot.incident_id != self.incident_id:
            raise ValueError("bundle and snapshot incident ID must match")
        _require_timezone_aware(self.created_at, "created_at")
        _require_json_safe(self.metadata, "bundle.metadata")
