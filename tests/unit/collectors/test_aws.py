import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from botocore.exceptions import ClientError

from pilo_incident_investigator.collectors.aws import (
    AlarmTargetEcsCollector,
    AlbTargetHealthCollector,
    AllPiloServicesCollector,
    RdsBasicStatusCollector,
    RecentGitHubDeploymentsCollector,
    StoppedTasksAndLogsCollector,
    default_collectors,
)
from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.event import incident_id_for, parse_alarm_event
from pilo_incident_investigator.integrations.github import Deployment
from pilo_incident_investigator.snapshot import (
    DEFAULT_COLLECTOR_NAMES,
    CollectionContext,
    CollectorError,
)
from pilo_incident_investigator.topology import Topology, TopologyDenied

FIXTURES = Path(__file__).parents[2] / "fixtures"


class RecordingClient:
    def __init__(self, responses: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str) -> Any:
        def call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append((operation, kwargs))
            queued = self.responses.get(operation, [])
            return queued.pop(0) if queued else {}

        return call


class RecordingGitHub:
    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime]] = []

    def recent_deployments(self, repository: str, since: datetime) -> tuple[Deployment, ...]:
        self.calls.append((repository, since))
        return (
            Deployment(
                deployment_id="101",
                environment="dev",
                revision="abcdef12",
                created_at=datetime(2026, 8, 1, tzinfo=UTC),
            ),
        )


def context() -> CollectionContext:
    event_payload = cast(
        dict[str, JsonValue],
        json.loads((FIXTURES / "events" / "alarm.json").read_text(encoding="utf-8")),
    )
    event = parse_alarm_event(event_payload)
    topology = Topology.load((FIXTURES / "topology" / "valid.yaml").read_text(encoding="utf-8"))
    return CollectionContext(
        incident_id=incident_id_for(event.event_id),
        event=event,
        topology=topology,
        services=topology.resolve_alarm(event.alarm_arn),
    )


def test_default_factory_matches_fixed_collector_order() -> None:
    ecs = RecordingClient()
    logs = RecordingClient()
    alb = RecordingClient()
    rds = RecordingClient()
    github = RecordingGitHub()

    collectors = default_collectors(ecs, logs, alb, rds, github)

    assert tuple(collector.name for collector in collectors) == DEFAULT_COLLECTOR_NAMES


def test_alarm_target_ecs_rejects_resource_before_sdk_call() -> None:
    client = RecordingClient()
    collection_context = context()
    denied_service = replace(collection_context.services[0], ecs_service="not-pilo")
    denied_context = replace(collection_context, services=(denied_service,))

    with pytest.raises(TopologyDenied):
        AlarmTargetEcsCollector(client).collect(denied_context)

    assert client.calls == []


def test_alarm_target_and_all_service_health_are_normalized_and_bounded() -> None:
    target_client = RecordingClient(
        {
            "describe_services": [
                {"services": [{"desiredCount": 1, "runningCount": 0, "pendingCount": 1}]}
            ]
        }
    )
    target = AlarmTargetEcsCollector(target_client).collect(context())

    all_client = RecordingClient(
        {
            "describe_services": [
                {
                    "services": [
                        {"serviceName": f"pilo-dev-service-{index:02d}", "runningCount": 1}
                        for index in range(1, 9)
                    ]
                }
            ]
        }
    )
    all_services = AllPiloServicesCollector(all_client).collect(context())

    assert target[0].data == {"desired": 1, "running": 0, "pending": 1}
    assert len(all_services) == 8
    assert len(all_client.calls) == 1
    assert len(all_client.calls[0][1]["services"]) == 8


def test_stopped_tasks_and_logs_use_bounded_pages_windows_and_limits() -> None:
    ecs = RecordingClient(
        {
            "list_tasks": [
                {"taskArns": ["task-1"], "nextToken": "page-2"},
                {"taskArns": ["task-2"], "nextToken": "ignored-page-3"},
            ],
            "describe_tasks": [
                {
                    "tasks": [
                        {"taskArn": "task-1", "stopCode": "EssentialContainerExited"},
                        {"taskArn": "task-2", "stopCode": "OutOfMemoryError"},
                    ]
                }
            ],
        }
    )
    logs = RecordingClient(
        {"filter_log_events": [{"events": [{"timestamp": 1, "message": "x" * 2000}]}]}
    )

    evidence = StoppedTasksAndLogsCollector(ecs, logs).collect(context())

    list_calls = [kwargs for operation, kwargs in ecs.calls if operation == "list_tasks"]
    log_calls = [kwargs for operation, kwargs in logs.calls if operation == "filter_log_events"]
    assert len(list_calls) == 2
    assert all(call["maxResults"] == 100 for call in list_calls)
    assert len(log_calls) == 1
    assert log_calls[0]["limit"] == 100
    assert log_calls[0]["endTime"] - log_calls[0]["startTime"] == 20 * 60 * 1000
    assert len(cast(str, evidence[-1].data["message"])) == 500


def test_alb_rds_and_github_collect_only_mapped_resources() -> None:
    alb = RecordingClient(
        {
            "describe_target_health": [
                {"TargetHealthDescriptions": [{"TargetHealth": {"State": "unhealthy"}}]}
            ]
        }
    )
    rds = RecordingClient(
        {"describe_db_instances": [{"DBInstances": [{"DBInstanceStatus": "available"}]}]}
    )
    github = RecordingGitHub()

    alb_evidence = AlbTargetHealthCollector(alb).collect(context())
    rds_evidence = RdsBasicStatusCollector(rds).collect(context())
    github_evidence = RecentGitHubDeploymentsCollector(github).collect(context())

    assert alb_evidence[0].data["states"] == ["unhealthy"]
    assert rds_evidence[0].data["status"] == "available"
    assert github_evidence[0].data["revision"] == "abcdef12"
    assert len(alb.calls) == len(rds.calls) == len(github.calls) == 1


def test_expected_sdk_error_becomes_sanitized_collector_error() -> None:
    sensitive_marker = "SENSITIVE-SDK-MARKER"

    class FailingClient(RecordingClient):
        def describe_services(self, **kwargs: Any) -> dict[str, Any]:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": sensitive_marker}},
                "DescribeServices",
            )

    with pytest.raises(CollectorError, match="collector failed") as captured:
        AlarmTargetEcsCollector(FailingClient()).collect(context())

    assert sensitive_marker not in str(captured.value)
    assert sensitive_marker not in repr(captured.value)
