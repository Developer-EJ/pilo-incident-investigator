"""Fail-closed registry for the five permitted additional investigation Tools."""

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from botocore.exceptions import BotoCoreError, ClientError

from pilo_incident_investigator.domain import (
    CollectorFailure,
    Evidence,
    JsonValue,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.integrations.github import ChangedFile, IntegrationError
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

MAX_LOG_EVENTS = 100
MAX_RDS_EVENTS = 100
MAX_CHANGED_FILES = 100
MAX_TEXT_LENGTH = 500
MAX_STATUS_LENGTH = 100
REQUEST_HASH_LENGTH = 16
LOG_LOOKBACK = timedelta(hours=1)
RDS_EVENT_DURATION_MINUTES = 60


class AwsClient(Protocol):
    def __getattr__(self, name: str) -> Callable[..., dict[str, Any]]: ...


class QueueMetricsReader(Protocol):
    def oldest_message_age_seconds(self, queue_url: str) -> int | None: ...


class ChangedFilesReader(Protocol):
    def changed_files(self, repository: str, limit: int) -> tuple[ChangedFile, ...]: ...


type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


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
        self._validate(request, topology, seen)
        result = self._handlers[request.tool].execute(request)
        seen.add(request.deduplication_key())
        return result

    def validate_batch(
        self,
        requests: tuple[ToolRequest, ...],
        topology: Topology,
        seen: set[str],
    ) -> None:
        """Validate a complete planner round without invoking a remote handler."""
        pending = set(seen)
        for request in requests:
            self._validate(request, topology, pending)
            pending.add(request.deduplication_key())

    def _validate(
        self,
        request: ToolRequest,
        topology: Topology,
        seen: set[str],
    ) -> None:
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


class ServiceLogSearchTool:
    """Read a fixed, bounded window from one pre-authorized log group."""

    def __init__(self, logs_client: AwsClient, *, clock: Clock = _utc_now) -> None:
        self._logs = logs_client
        self._clock = clock

    def execute(self, request: ToolRequest) -> ToolResult:
        observed_at = self._clock()
        try:
            response = self._logs.filter_log_events(
                logGroupName=request.resource_key,
                startTime=int((observed_at - LOG_LOOKBACK).timestamp() * 1000),
                endTime=int(observed_at.timestamp() * 1000),
                limit=MAX_LOG_EVENTS,
            )
            rows = _required_mappings(response, "events")
            normalized = sorted(
                (_normalize_log_event(row, request.resource_key) for row in rows),
                key=lambda item: (
                    cast(int, item["timestamp"]),
                    cast(str, item["message"]),
                    cast(str, item.get("log_stream", "")),
                ),
            )[:MAX_LOG_EVENTS]
        except (BotoCoreError, ClientError, IntegrationError, OSError, TimeoutError):
            return _failure(request, "aws_api_error", "bounded log search failed")
        except _InvalidResponse:
            return _failure(request, "invalid_response", "bounded log search response was invalid")
        return _evidence_result(
            request, "service-log-search", "service log event", observed_at, normalized
        )


class RdsEventsTool:
    """Read a fixed number of recent events for one pre-authorized RDS instance."""

    def __init__(self, rds_client: AwsClient, *, clock: Clock = _utc_now) -> None:
        self._rds = rds_client
        self._clock = clock

    def execute(self, request: ToolRequest) -> ToolResult:
        observed_at = self._clock()
        try:
            response = self._rds.describe_events(
                SourceIdentifier=request.resource_key,
                SourceType="db-instance",
                Duration=RDS_EVENT_DURATION_MINUTES,
                MaxRecords=MAX_RDS_EVENTS,
            )
            rows = _required_mappings(response, "Events")
            normalized = sorted(
                (_normalize_rds_event(row, request.resource_key) for row in rows),
                key=lambda item: (cast(str, item["occurred_at"]), cast(str, item["message"])),
            )[:MAX_RDS_EVENTS]
        except (BotoCoreError, ClientError, IntegrationError, OSError, TimeoutError):
            return _failure(request, "aws_api_error", "bounded RDS events request failed")
        except _InvalidResponse:
            return _failure(request, "invalid_response", "bounded RDS events response was invalid")
        return _evidence_result(request, "rds-events", "RDS event", observed_at, normalized)


class SecretRotationMetadataTool:
    """Read non-sensitive rotation metadata for one pre-authorized secret."""

    def __init__(self, secrets_client: AwsClient, *, clock: Clock = _utc_now) -> None:
        self._secrets = secrets_client
        self._clock = clock

    def execute(self, request: ToolRequest) -> ToolResult:
        observed_at = self._clock()
        try:
            response = self._secrets.describe_secret(SecretId=request.resource_key)
            data = _normalize_secret_metadata(response)
        except (BotoCoreError, ClientError, IntegrationError, OSError, TimeoutError):
            return _failure(request, "aws_api_error", "bounded secret metadata request failed")
        except _InvalidResponse:
            return _failure(
                request, "invalid_response", "bounded secret metadata response was invalid"
            )
        return _evidence_result(
            request,
            "secret-rotation-metadata",
            "secret rotation metadata",
            observed_at,
            [data],
        )


class SqsStatusTool:
    """Read queue counters and an optional read-only oldest-message metric."""

    def __init__(
        self,
        sqs_client: AwsClient,
        metrics: QueueMetricsReader | None = None,
        *,
        clock: Clock = _utc_now,
    ) -> None:
        self._sqs = sqs_client
        self._metrics = metrics
        self._clock = clock

    def execute(self, request: ToolRequest) -> ToolResult:
        observed_at = self._clock()
        try:
            response = self._sqs.get_queue_attributes(
                QueueUrl=request.resource_key,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "ApproximateNumberOfMessagesDelayed",
                ],
            )
            data = _normalize_queue_attributes(response, request.resource_key)
            if self._metrics is not None:
                oldest_age = self._metrics.oldest_message_age_seconds(request.resource_key)
                if oldest_age is not None:
                    if (
                        isinstance(oldest_age, bool)
                        or not isinstance(oldest_age, int)
                        or oldest_age < 0
                    ):
                        raise _InvalidResponse
                    data["oldest_message_age_seconds"] = oldest_age
        except (BotoCoreError, ClientError, IntegrationError, OSError, TimeoutError):
            return _failure(request, "aws_api_error", "bounded queue status request failed")
        except _InvalidResponse:
            return _failure(
                request, "invalid_response", "bounded queue status response was invalid"
            )
        return _evidence_result(request, "sqs-status", "SQS queue status", observed_at, [data])


class GitHubChangedFilesTool:
    """Read a bounded file-name/status list without requesting file contents."""

    def __init__(self, github: ChangedFilesReader, *, clock: Clock = _utc_now) -> None:
        self._github = github
        self._clock = clock

    def execute(self, request: ToolRequest) -> ToolResult:
        observed_at = self._clock()
        try:
            files = self._github.changed_files(request.resource_key, MAX_CHANGED_FILES)
            if not isinstance(files, tuple):
                raise _InvalidResponse
            normalized = sorted(
                (
                    _normalize_changed_file(item, request.resource_key)
                    for item in files[:MAX_CHANGED_FILES]
                ),
                key=lambda item: (cast(str, item["path"]), cast(str, item["status"])),
            )
        except _InvalidResponse:
            return _failure(
                request, "invalid_response", "bounded changed-files response was invalid"
            )
        except (IntegrationError, OSError, TimeoutError, TypeError, ValueError):
            return _failure(request, "github_api_error", "bounded changed-files request failed")
        return _evidence_result(
            request, "github-changed-files", "GitHub changed file", observed_at, normalized
        )


class _InvalidResponse(ValueError):
    """Internal marker for a response that cannot become safe Evidence."""


def _failure(request: ToolRequest, code: str, detail: str) -> ToolResult:
    return ToolResult(
        request=request,
        evidence=(),
        failure=CollectorFailure(collector=request.tool, code=code, detail=detail),
    )


def _evidence_result(
    request: ToolRequest,
    local_prefix: str,
    summary: str,
    observed_at: datetime,
    rows: list[dict[str, JsonValue]],
) -> ToolResult:
    request_hash = request.deduplication_key()[len("tool-") : len("tool-") + REQUEST_HASH_LENGTH]
    evidence = tuple(
        Evidence(
            evidence_id=f"tool-local-{local_prefix}-{request_hash}-{index}",
            source=request.tool,
            observed_at=observed_at,
            summary=summary,
            data=row,
        )
        for index, row in enumerate(rows, start=1)
    )
    return ToolResult(request=request, evidence=evidence, failure=None)


def _required_mappings(response: object, key: str) -> list[dict[str, Any]]:
    if not isinstance(response, dict):
        raise _InvalidResponse
    rows = response.get(key)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise _InvalidResponse
    return cast(list[dict[str, Any]], rows)


def _normalize_log_event(row: dict[str, Any], log_group: str) -> dict[str, JsonValue]:
    timestamp = row.get("timestamp")
    message = row.get("message")
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or not isinstance(message, str)
    ):
        raise _InvalidResponse
    data: dict[str, JsonValue] = {
        "log_group": log_group,
        "timestamp": timestamp,
        "message": _bounded_text(message),
    }
    stream = row.get("logStreamName")
    if isinstance(stream, str) and stream:
        data["log_stream"] = _bounded_text(stream)
    return data


def _normalize_rds_event(row: dict[str, Any], database: str) -> dict[str, JsonValue]:
    occurred_at = row.get("Date")
    message = row.get("Message")
    if not isinstance(occurred_at, datetime) or not isinstance(message, str):
        raise _InvalidResponse
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise _InvalidResponse
    return {
        "database": database,
        "occurred_at": occurred_at.astimezone(UTC).isoformat(),
        "message": _bounded_text(message),
    }


def _normalize_secret_metadata(response: object) -> dict[str, JsonValue]:
    if not isinstance(response, dict):
        raise _InvalidResponse
    rotation_enabled = response.get("RotationEnabled")
    if not isinstance(rotation_enabled, bool):
        raise _InvalidResponse
    stages_by_version = response.get("VersionIdsToStages", {})
    if not isinstance(stages_by_version, dict):
        raise _InvalidResponse
    stages: set[str] = set()
    for value in stages_by_version.values():
        if not isinstance(value, list) or any(
            not isinstance(stage, str) or not stage for stage in value
        ):
            raise _InvalidResponse
        stages.update(value)
    version_stages: list[JsonValue] = []
    version_stages.extend(sorted(stages))
    return {
        "rotation_enabled": rotation_enabled,
        "last_rotated_at": _optional_datetime(response.get("LastRotatedDate")),
        "last_changed_at": _optional_datetime(response.get("LastChangedDate")),
        "version_stages": version_stages,
    }


def _normalize_queue_attributes(response: object, queue: str) -> dict[str, JsonValue]:
    if not isinstance(response, dict) or not isinstance(response.get("Attributes"), dict):
        raise _InvalidResponse
    attributes = cast(dict[str, object], response["Attributes"])
    return {
        "queue": queue,
        "visible": _count_attribute(attributes, "ApproximateNumberOfMessages"),
        "not_visible": _count_attribute(attributes, "ApproximateNumberOfMessagesNotVisible"),
        "delayed": _count_attribute(attributes, "ApproximateNumberOfMessagesDelayed"),
    }


def _normalize_changed_file(file: ChangedFile, repository: str) -> dict[str, JsonValue]:
    if not isinstance(file, ChangedFile) or not file.path or not file.status:
        raise _InvalidResponse
    return {
        "repository": repository,
        "path": _bounded_text(file.path),
        "status": file.status[:MAX_STATUS_LENGTH],
    }


def _optional_datetime(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise _InvalidResponse
    return value.astimezone(UTC).isoformat()


def _count_attribute(attributes: dict[str, object], name: str) -> int:
    value = attributes.get(name)
    if not isinstance(value, str) or not value.isdecimal():
        raise _InvalidResponse
    return int(value)


def _bounded_text(value: str) -> str:
    return value[:MAX_TEXT_LENGTH]
