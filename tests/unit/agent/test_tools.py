from datetime import UTC, datetime
from typing import Any, cast

import boto3
import pytest
from botocore.stub import Stubber

from pilo_incident_investigator.agent.tools import (
    AwsClient,
    GitHubChangedFilesTool,
    RdsEventsTool,
    SecretRotationMetadataTool,
    ServiceLogSearchTool,
    SqsStatusTool,
)
from pilo_incident_investigator.domain import JsonValue, ToolRequest
from pilo_incident_investigator.integrations.github import ChangedFile, IntegrationError


class RecordingClient:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str) -> Any:
        def call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append((operation, kwargs))
            return self.response

        return call


class RecordingMetrics:
    def __init__(self, oldest_age_seconds: int | None) -> None:
        self.oldest_age_seconds = oldest_age_seconds
        self.queues: list[str] = []

    def oldest_message_age_seconds(self, queue_url: str) -> int | None:
        self.queues.append(queue_url)
        return self.oldest_age_seconds


class RecordingChangedFiles:
    def __init__(self, files: tuple[ChangedFile, ...]) -> None:
        self.files = files
        self.calls: list[tuple[str, int]] = []

    def changed_files(self, repository: str, limit: int) -> tuple[ChangedFile, ...]:
        self.calls.append((repository, limit))
        return self.files


def request_for(
    tool: str,
    resource_key: str,
    parameters: dict[str, JsonValue] | None = None,
) -> ToolRequest:
    return ToolRequest(
        tool=tool,
        resource_key=resource_key,
        parameters={} if parameters is None else parameters,
        reason="synthetic investigation reason",
    )


def now() -> datetime:
    return datetime(2026, 8, 1, 12, tzinfo=UTC)


def expected_evidence_id(request: ToolRequest, prefix: str, index: int) -> str:
    return f"tool-local-{prefix}-{request.deduplication_key()[5:21]}-{index}"


def test_service_log_search_bounds_request_and_truncates_normalized_evidence() -> None:
    logs = RecordingClient(
        {
            "events": [
                {"timestamp": 1_000, "message": "x" * 600, "logStreamName": "stream-1"},
                {"timestamp": 2_000, "message": "later"},
            ]
        }
    )

    result = ServiceLogSearchTool(logs, clock=now).execute(
        request_for("service_log_search", "/aws/ecs/pilo-dev-service-01")
    )

    assert result.failure is None
    assert [item.evidence_id for item in result.evidence] == [
        expected_evidence_id(result.request, "service-log-search", 1),
        expected_evidence_id(result.request, "service-log-search", 2),
    ]
    assert result.evidence[0].data == {
        "log_group": "/aws/ecs/pilo-dev-service-01",
        "timestamp": 1_000,
        "message": "x" * 500,
        "log_stream": "stream-1",
    }
    _, call = logs.calls[0]
    assert call["logGroupName"] == "/aws/ecs/pilo-dev-service-01"
    assert call["limit"] == 100
    assert call["endTime"] - call["startTime"] == 60 * 60 * 1000


def test_rds_events_is_bounded_and_normalizes_response() -> None:
    rds = RecordingClient(
        {
            "Events": [
                {
                    "Date": datetime(2026, 8, 1, 11, 30, tzinfo=UTC),
                    "Message": "maintenance window",
                    "SourceIdentifier": "pilo-dev-db-01",
                }
            ]
        }
    )

    result = RdsEventsTool(rds, clock=now).execute(request_for("rds_events", "pilo-dev-db-01"))

    assert result.failure is None
    assert result.evidence[0].evidence_id == expected_evidence_id(result.request, "rds-events", 1)
    assert result.evidence[0].data == {
        "database": "pilo-dev-db-01",
        "occurred_at": "2026-08-01T11:30:00+00:00",
        "message": "maintenance window",
    }
    _, call = rds.calls[0]
    assert call == {
        "SourceIdentifier": "pilo-dev-db-01",
        "SourceType": "db-instance",
        "Duration": 60,
        "MaxRecords": 100,
    }


def test_secret_rotation_metadata_uses_only_describe_secret() -> None:
    version_identifier = "synthetic-version-identifier-0001"
    client = boto3.client(
        "secretsmanager",
        region_name="ap-northeast-2",
        aws_access_key_id="synthetic-access-key",
        aws_secret_access_key="synthetic-secret-key",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "describe_secret",
        {
            "ARN": "arn:aws:secretsmanager:ap-northeast-2:000000000000:secret:synthetic",
            "Name": "pilo-dev-secret-01",
            "RotationEnabled": True,
            "LastRotatedDate": datetime(2026, 7, 31, tzinfo=UTC),
            "LastChangedDate": datetime(2026, 8, 1, tzinfo=UTC),
            "VersionIdsToStages": {version_identifier: ["AWSCURRENT", "AWSPREVIOUS"]},
        },
        {"SecretId": "pilo-dev-secret-01"},
    )

    with stubber:
        result = SecretRotationMetadataTool(cast(AwsClient, client), clock=now).execute(
            request_for("secret_rotation_metadata", "pilo-dev-secret-01")
        )

    assert result.failure is None
    assert result.evidence[0].evidence_id == expected_evidence_id(
        result.request, "secret-rotation-metadata", 1
    )
    assert result.evidence[0].data == {
        "rotation_enabled": True,
        "last_rotated_at": "2026-07-31T00:00:00+00:00",
        "last_changed_at": "2026-08-01T00:00:00+00:00",
        "version_stages": ["AWSCURRENT", "AWSPREVIOUS"],
    }
    assert version_identifier not in repr(result.evidence[0].data)


def test_evidence_ids_are_stable_per_request_and_unique_across_resources() -> None:
    response = {"events": [{"timestamp": 1_000, "message": "same event"}]}
    first_request = request_for("service_log_search", "/aws/ecs/pilo-dev-service-01")
    second_request = request_for("service_log_search", "/aws/ecs/pilo-dev-service-02")

    first = ServiceLogSearchTool(RecordingClient(response), clock=now).execute(first_request)
    repeated = ServiceLogSearchTool(RecordingClient(response), clock=now).execute(first_request)
    second = ServiceLogSearchTool(RecordingClient(response), clock=now).execute(second_request)

    assert first.evidence[0].evidence_id == repeated.evidence[0].evidence_id
    assert first.evidence[0].evidence_id != second.evidence[0].evidence_id


def test_sqs_status_uses_queue_attributes_and_optional_oldest_message_metric() -> None:
    queue_url = "https://sqs.ap-northeast-2.amazonaws.com/000000000000/pilo-dev-queue-01"
    sqs = RecordingClient(
        {
            "Attributes": {
                "ApproximateNumberOfMessages": "2",
                "ApproximateNumberOfMessagesNotVisible": "3",
                "ApproximateNumberOfMessagesDelayed": "4",
            }
        }
    )
    metrics = RecordingMetrics(oldest_age_seconds=72)

    result = SqsStatusTool(sqs, metrics, clock=now).execute(request_for("sqs_status", queue_url))

    assert result.failure is None
    assert result.evidence[0].data == {
        "queue": queue_url,
        "visible": 2,
        "not_visible": 3,
        "delayed": 4,
        "oldest_message_age_seconds": 72,
    }
    assert sqs.calls == [
        (
            "get_queue_attributes",
            {
                "QueueUrl": queue_url,
                "AttributeNames": [
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "ApproximateNumberOfMessagesDelayed",
                ],
            },
        )
    ]
    assert metrics.queues == [queue_url]


def test_secret_and_metrics_failures_are_sanitized() -> None:
    sensitive_marker = "SENSITIVE-DEPENDENCY-MESSAGE"

    class FailingSecretClient:
        def describe_secret(self, **kwargs: Any) -> dict[str, Any]:
            raise IntegrationError(sensitive_marker)

    class FailingMetrics:
        def oldest_message_age_seconds(self, queue_url: str) -> int | None:
            raise OSError(sensitive_marker)

    secret_result = SecretRotationMetadataTool(
        cast(AwsClient, FailingSecretClient()), clock=now
    ).execute(request_for("secret_rotation_metadata", "pilo-dev-secret-01"))
    queue_result = SqsStatusTool(
        RecordingClient(
            {
                "Attributes": {
                    "ApproximateNumberOfMessages": "0",
                    "ApproximateNumberOfMessagesNotVisible": "0",
                    "ApproximateNumberOfMessagesDelayed": "0",
                }
            }
        ),
        FailingMetrics(),
        clock=now,
    ).execute(
        request_for(
            "sqs_status",
            "https://sqs.ap-northeast-2.amazonaws.com/000000000000/pilo-dev-queue-01",
        )
    )

    for result in (secret_result, queue_result):
        assert result.evidence == ()
        assert result.failure is not None
        assert sensitive_marker not in result.failure.detail


def test_github_changed_files_is_bounded_and_excludes_content() -> None:
    files = tuple(
        ChangedFile(path=f"src/{index:03}.py", status="modified") for index in range(100, -1, -1)
    )
    github = RecordingChangedFiles(files)

    result = GitHubChangedFilesTool(github, clock=now).execute(
        request_for("github_changed_files", "synthetic-org/pilo-dev-service-01")
    )

    assert result.failure is None
    assert len(result.evidence) == 100
    assert result.evidence[0].data == {
        "repository": "synthetic-org/pilo-dev-service-01",
        "path": "src/001.py",
        "status": "modified",
    }
    assert result.evidence[-1].data["path"] == "src/100.py"
    assert github.calls == [("synthetic-org/pilo-dev-service-01", 100)]


def test_github_changed_files_malformed_result_becomes_sanitized_failure() -> None:
    sensitive_marker = "SENSITIVE-GITHUB-MESSAGE"

    class MalformedChangedFiles:
        def changed_files(self, repository: str, limit: int) -> tuple[ChangedFile, ...]:
            raise ValueError(sensitive_marker)

    result = GitHubChangedFilesTool(MalformedChangedFiles(), clock=now).execute(
        request_for("github_changed_files", "synthetic-org/pilo-dev-service-01")
    )

    assert result.evidence == ()
    assert result.failure is not None
    assert sensitive_marker not in result.failure.detail


def test_github_changed_files_integration_failure_is_sanitized() -> None:
    sensitive_marker = "SENSITIVE-GITHUB-INTEGRATION-MESSAGE"

    class FailingChangedFiles:
        def changed_files(self, repository: str, limit: int) -> tuple[ChangedFile, ...]:
            raise IntegrationError(sensitive_marker)

    result = GitHubChangedFilesTool(FailingChangedFiles(), clock=now).execute(
        request_for("github_changed_files", "synthetic-org/pilo-dev-service-01")
    )

    assert result.evidence == ()
    assert result.failure is not None
    assert sensitive_marker not in result.failure.detail


@pytest.mark.parametrize("tool", ["service_log_search", "rds_events", "sqs_status"])
def test_sdk_failures_are_sanitized(tool: str) -> None:
    sensitive_marker = "SENSITIVE-REMOTE-MESSAGE"

    class FailingClient:
        def __getattr__(self, operation: str) -> Any:
            def call(**kwargs: Any) -> dict[str, Any]:
                raise IntegrationError(sensitive_marker)

            return call

    request = request_for(tool, "synthetic-resource")
    if tool == "service_log_search":
        result = ServiceLogSearchTool(FailingClient(), clock=now).execute(request)
    elif tool == "rds_events":
        result = RdsEventsTool(FailingClient(), clock=now).execute(request)
    else:
        result = SqsStatusTool(FailingClient(), RecordingMetrics(None), clock=now).execute(request)

    assert result.evidence == ()
    assert result.failure is not None
    assert sensitive_marker not in result.failure.detail
