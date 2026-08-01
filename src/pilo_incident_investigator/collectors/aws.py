"""Bounded read-only collectors for the deterministic PILO Snapshot."""

from collections import defaultdict
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Protocol, cast

from botocore.exceptions import BotoCoreError, ClientError

from pilo_incident_investigator.domain import Evidence, JsonValue
from pilo_incident_investigator.integrations.github import Deployment, IntegrationError
from pilo_incident_investigator.snapshot import CollectionContext, Collector, CollectorError

MAX_TASK_PAGES = 2
MAX_TASKS = 100
MAX_LOG_EVENTS = 100
MAX_TEXT_LENGTH = 500
LOG_LOOKBACK = timedelta(minutes=15)
LOG_LOOKAHEAD = timedelta(minutes=5)
DEPLOYMENT_LOOKBACK = timedelta(hours=24)


class AwsClient(Protocol):
    def __getattr__(self, name: str) -> Callable[..., dict[str, Any]]: ...


class DeploymentReader(Protocol):
    def recent_deployments(self, repository: str, since: Any) -> tuple[Deployment, ...]: ...


class AlarmTargetEcsCollector:
    name = "alarm_target_ecs"

    def __init__(self, ecs_client: AwsClient) -> None:
        self._ecs = ecs_client

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        for service in context.services:
            context.topology.require_allowed("ecs_cluster", service.ecs_cluster)
            context.topology.require_allowed("ecs_service", service.ecs_service)
            response = _aws_call(
                self._ecs.describe_services,
                cluster=service.ecs_cluster,
                services=[service.ecs_service],
            )
            rows = response.get("services", [])
            row = rows[0] if isinstance(rows, list) and rows else {}
            data: dict[str, JsonValue] = {
                "desired": _integer(row, "desiredCount"),
                "running": _integer(row, "runningCount"),
                "pending": _integer(row, "pendingCount"),
            }
            evidence.append(_evidence(context, "ecs.describe_services", "target ECS state", data))
        return tuple(evidence)


class StoppedTasksAndLogsCollector:
    name = "stopped_tasks_and_logs"

    def __init__(self, ecs_client: AwsClient, logs_client: AwsClient) -> None:
        self._ecs = ecs_client
        self._logs = logs_client

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        for service in context.services:
            task_arns: list[str] = []
            next_token: str | None = None
            for _ in range(MAX_TASK_PAGES):
                context.topology.require_allowed("ecs_cluster", service.ecs_cluster)
                context.topology.require_allowed("ecs_service", service.ecs_service)
                request: dict[str, Any] = {
                    "cluster": service.ecs_cluster,
                    "serviceName": service.ecs_service,
                    "desiredStatus": "STOPPED",
                    "maxResults": MAX_TASKS,
                }
                if next_token is not None:
                    request["nextToken"] = next_token
                response = _aws_call(self._ecs.list_tasks, **request)
                task_arns.extend(_strings(response.get("taskArns")))
                next_token = _optional_string(response.get("nextToken"))
                if next_token is None or len(task_arns) >= MAX_TASKS:
                    break
            task_arns = task_arns[:MAX_TASKS]
            if task_arns:
                context.topology.require_allowed("ecs_cluster", service.ecs_cluster)
                context.topology.require_allowed("ecs_service", service.ecs_service)
                response = _aws_call(
                    self._ecs.describe_tasks,
                    cluster=service.ecs_cluster,
                    tasks=task_arns,
                )
                for task in _mappings(response.get("tasks")):
                    evidence.append(
                        _evidence(
                            context,
                            "ecs.describe_tasks",
                            "stopped ECS task",
                            {
                                "task": _bounded_text(task.get("taskArn")),
                                "stop_code": _bounded_text(task.get("stopCode")),
                            },
                        )
                    )

            start = int((context.event.state_timestamp - LOG_LOOKBACK).timestamp() * 1000)
            end = int((context.event.state_timestamp + LOG_LOOKAHEAD).timestamp() * 1000)
            for log_group in service.log_groups:
                context.topology.require_allowed("log_group", log_group)
                response = _aws_call(
                    self._logs.filter_log_events,
                    logGroupName=log_group,
                    startTime=start,
                    endTime=end,
                    limit=MAX_LOG_EVENTS,
                )
                for event in _mappings(response.get("events"))[:MAX_LOG_EVENTS]:
                    evidence.append(
                        _evidence(
                            context,
                            "logs.filter_log_events",
                            "bounded service log event",
                            {
                                "timestamp": _integer(event, "timestamp"),
                                "message": _bounded_text(event.get("message")),
                            },
                        )
                    )
        return tuple(evidence)


class AlbTargetHealthCollector:
    name = "alb_target_health"

    def __init__(self, elbv2_client: AwsClient) -> None:
        self._elbv2 = elbv2_client

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        for service in context.services:
            for target_group in service.target_groups:
                context.topology.require_allowed("target_group", target_group)
                response = _aws_call(
                    self._elbv2.describe_target_health, TargetGroupArn=target_group
                )
                states: list[JsonValue] = [
                    _bounded_text(item.get("TargetHealth", {}).get("State"))
                    for item in _mappings(response.get("TargetHealthDescriptions"))
                    if isinstance(item.get("TargetHealth"), dict)
                ]
                evidence.append(
                    _evidence(
                        context,
                        "elbv2.describe_target_health",
                        "ALB target health",
                        {"states": states},
                    )
                )
        return tuple(evidence)


class AllPiloServicesCollector:
    name = "all_pilo_services"

    def __init__(self, ecs_client: AwsClient) -> None:
        self._ecs = ecs_client

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        by_cluster: dict[str, list[Any]] = defaultdict(list)
        for service in context.topology.services:
            by_cluster[service.ecs_cluster].append(service)
        evidence: list[Evidence] = []
        for cluster, services in by_cluster.items():
            context.topology.require_allowed("ecs_cluster", cluster)
            for service in services:
                context.topology.require_allowed("ecs_service", service.ecs_service)
            response = _aws_call(
                self._ecs.describe_services,
                cluster=cluster,
                services=[service.ecs_service for service in services],
            )
            for row in _mappings(response.get("services")):
                evidence.append(
                    _evidence(
                        context,
                        "ecs.describe_services.all_pilo",
                        "PILO service running state",
                        {
                            "service": _bounded_text(row.get("serviceName")),
                            "running": _integer(row, "runningCount"),
                        },
                    )
                )
        return tuple(evidence)


class RecentGitHubDeploymentsCollector:
    name = "recent_github_deployments"

    def __init__(self, github: DeploymentReader) -> None:
        self._github = github

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        seen: set[str] = set()
        since = context.event.state_timestamp - DEPLOYMENT_LOOKBACK
        for service in context.services:
            repository = service.github_repository
            if repository in seen:
                continue
            seen.add(repository)
            context.topology.require_allowed("github_repository", repository)
            try:
                deployments = self._github.recent_deployments(repository, since)
            except IntegrationError:
                raise CollectorError("github_api_error", "bounded GitHub request failed") from None
            for deployment in deployments:
                evidence.append(
                    _evidence(
                        context,
                        "github.deployments",
                        "recent GitHub deployment",
                        {
                            "deployment_id": deployment.deployment_id,
                            "environment": deployment.environment,
                            "revision": _bounded_text(deployment.revision),
                            "created_at": deployment.created_at.isoformat(),
                        },
                    )
                )
        return tuple(evidence)


class RdsBasicStatusCollector:
    name = "rds_basic_status"

    def __init__(self, rds_client: AwsClient) -> None:
        self._rds = rds_client

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        seen: set[str] = set()
        for service in context.services:
            for database in service.rds_instances:
                if database in seen:
                    continue
                seen.add(database)
                context.topology.require_allowed("rds_instance", database)
                response = _aws_call(self._rds.describe_db_instances, DBInstanceIdentifier=database)
                rows = _mappings(response.get("DBInstances"))
                row = rows[0] if rows else {}
                evidence.append(
                    _evidence(
                        context,
                        "rds.describe_db_instances",
                        "RDS basic status",
                        {"status": _bounded_text(row.get("DBInstanceStatus"))},
                    )
                )
        return tuple(evidence)


def default_collectors(
    ecs_client: AwsClient,
    logs_client: AwsClient,
    elbv2_client: AwsClient,
    rds_client: AwsClient,
    github: DeploymentReader,
) -> tuple[Collector, ...]:
    return (
        AlarmTargetEcsCollector(ecs_client),
        StoppedTasksAndLogsCollector(ecs_client, logs_client),
        AlbTargetHealthCollector(elbv2_client),
        AllPiloServicesCollector(ecs_client),
        RecentGitHubDeploymentsCollector(github),
        RdsBasicStatusCollector(rds_client),
    )


def _aws_call(operation: Callable[..., dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    try:
        return operation(**kwargs)
    except (BotoCoreError, ClientError):
        raise CollectorError("aws_api_error", "bounded AWS collector request failed") from None


def _evidence(
    context: CollectionContext,
    source: str,
    summary: str,
    data: dict[str, JsonValue],
) -> Evidence:
    return Evidence(
        evidence_id="collector-local",
        source=source,
        observed_at=context.event.state_timestamp,
        summary=summary,
        data=data,
    )


def _mappings(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, Any], item) for item in value if isinstance(item, dict)]


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(mapping: object, key: str) -> int:
    if not isinstance(mapping, dict):
        return 0
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _bounded_text(value: object) -> str:
    return value[:MAX_TEXT_LENGTH] if isinstance(value, str) else ""
