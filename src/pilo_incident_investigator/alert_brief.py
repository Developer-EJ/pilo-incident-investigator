"""Deterministic, evidence-only Slack Alert Brief rendering."""

import re
from collections import Counter
from collections.abc import Callable
from typing import Final

from pilo_incident_investigator.domain import Evidence, IncidentBundle
from pilo_incident_investigator.redaction import Redactor, UnsafeBundleError
from pilo_incident_investigator.topology import ServiceTopology, Topology

MAX_ALERT_BRIEF_CHARS: Final = 500
_NO_FACTS: Final = "확인: 확인 가능한 기본 상태가 없습니다"
_FAILURE_LABELS: Final = {
    "alarm_target_ecs": "ECS",
    "all_pilo_services": "ECS",
    "stopped_tasks_and_logs": "로그",
    "alb_target_health": "ALB",
    "recent_github_deployments": "GitHub 배포",
    "rds_basic_status": "RDS",
}
_DISPLAY_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}")
_ACCOUNT_ID: Final = re.compile(r"(?<!\d)\d{12}(?!\d)")
_GIT_REVISION: Final = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{7,64}(?![A-Za-z0-9])")
_AWS_ARN: Final = re.compile(r"arn:aws(?:-[a-z]+)?:", re.IGNORECASE)
_SQS_URL: Final = re.compile(r"https://sqs\.[^/]+/", re.IGNORECASE)
_TARGET_STATES: Final = frozenset(
    {"healthy", "initial", "unhealthy", "unused", "draining", "unavailable"}
)
_RDS_STATUSES: Final = frozenset(
    {
        "available",
        "backing-up",
        "creating",
        "deleting",
        "failed",
        "maintenance",
        "modifying",
        "rebooting",
        "starting",
        "stopped",
        "stopping",
        "storage-full",
        "upgrading",
    }
)


def render_slack_alert_brief(bundle: IncidentBundle, topology: Topology) -> str:
    """Render a bounded Brief from validated topology and Snapshot evidence only."""
    if not isinstance(bundle, IncidentBundle) or not isinstance(topology, Topology):
        raise UnsafeBundleError("alert brief inputs are invalid")

    services = topology.resolve_alarm(bundle.alarm.alarm_arn)
    service_keys = tuple(_safe_identifier(service.key) for service in services)
    target = ", ".join(service_keys) if service_keys else "미등록 대상"
    priority = topology.operations_for_alarm(bundle.alarm.alarm_arn).priority
    if priority not in {"P1", "P2", "P3"}:
        raise UnsafeBundleError("alert brief priority is invalid")
    alarm_name = _safe_identifier(bundle.alarm.alarm_name)

    facts = _facts_for(bundle.snapshot.evidence, services)
    lines = [
        f"[PILO][{priority}][ALARM] {target}",
        f"Alarm: {alarm_name}",
        f"확인: {'; '.join(facts)}" if facts else _NO_FACTS,
        _render_failures(bundle),
    ]
    if len(services) == 1:
        operations = topology.operations_for_service(services[0].key)
        owner = "미등록" if operations.owner is None else _safe_line(operations.owner, maximum=80)
        runbook = (
            "미등록"
            if operations.runbook_url is None
            else _safe_line(operations.runbook_url, maximum=512)
        )
        lines.extend((f"담당: {owner}", f"Runbook: {runbook}"))
    return _bounded_lines(lines)


def _facts_for(
    evidence: tuple[Evidence, ...], services: tuple[ServiceTopology, ...]
) -> tuple[str, ...]:
    if len(services) != 1:
        return ()
    service = services[0]
    renderers: tuple[Callable[[], str | None], ...] = (
        lambda: _render_running_fact(evidence, service.key),
        lambda: _render_stopped_task_fact(evidence, service.key),
        lambda: _render_target_health_fact(evidence, service.key, frozenset(service.target_groups)),
        lambda: _render_rds_fact(evidence, frozenset(service.rds_instances)),
        lambda: _render_deployment_fact(evidence, service.github_repository),
    )
    facts: list[str] = []
    for renderer in renderers:
        rendered = renderer()
        if rendered is not None:
            facts.append(rendered)
        if len(facts) == 3:
            break
    return tuple(facts)


def _render_running_fact(evidence: tuple[Evidence, ...], service_key: str) -> str | None:
    for item in evidence:
        if item.source not in {"ecs.describe_services", "ecs.describe_services.all_pilo"}:
            continue
        if set(item.data) != {"service", "desired", "running", "pending"}:
            continue
        if item.data["service"] != service_key:
            continue
        desired = item.data["desired"]
        running = item.data["running"]
        pending = item.data["pending"]
        if not all(_is_non_negative_integer(value) for value in (desired, running, pending)):
            continue
        return f"running {running}/{desired}"
    return None


def _render_stopped_task_fact(evidence: tuple[Evidence, ...], service_key: str) -> str | None:
    count = sum(
        1
        for item in evidence
        if item.source == "ecs.describe_tasks"
        and set(item.data) == {"service", "task", "stop_code"}
        and item.data["service"] == service_key
        and isinstance(item.data["task"], str)
        and isinstance(item.data["stop_code"], str)
    )
    return f"stopped task {count}건" if count else None


def _render_target_health_fact(
    evidence: tuple[Evidence, ...], service_key: str, allowed_target_groups: frozenset[str]
) -> str | None:
    unhealthy_count = 0
    found = False
    for item in evidence:
        if item.source != "elbv2.describe_target_health":
            continue
        if set(item.data) != {"service", "target_group", "states"}:
            continue
        target_group = item.data["target_group"]
        if (
            item.data["service"] != service_key
            or not isinstance(target_group, str)
            or target_group not in allowed_target_groups
        ):
            continue
        states = item.data["states"]
        if not isinstance(states, list) or any(
            not isinstance(state, str) or state not in _TARGET_STATES for state in states
        ):
            continue
        found = True
        unhealthy_count += sum(state != "healthy" for state in states)
    return f"unhealthy target {unhealthy_count}개" if found and unhealthy_count else None


def _render_rds_fact(
    evidence: tuple[Evidence, ...], allowed_databases: frozenset[str]
) -> str | None:
    for item in evidence:
        if item.source != "rds.describe_db_instances":
            continue
        if set(item.data) != {"database", "status"}:
            continue
        database = item.data["database"]
        status = item.data["status"]
        if (
            not isinstance(database, str)
            or database not in allowed_databases
            or not isinstance(status, str)
            or status not in _RDS_STATUSES
            or status == "available"
        ):
            continue
        try:
            safe_status = _safe_line(status, maximum=64)
        except UnsafeBundleError:
            continue
        return f"RDS {safe_status}"
    return None


def _render_deployment_fact(evidence: tuple[Evidence, ...], repository: str) -> str | None:
    for item in evidence:
        if item.source != "github.deployments":
            continue
        if set(item.data) != {
            "repository",
            "deployment_id",
            "environment",
            "revision",
            "created_at",
        }:
            continue
        if item.data["repository"] != repository:
            continue
        if not all(
            isinstance(item.data[key], str) and bool(item.data[key])
            for key in ("deployment_id", "environment", "revision", "created_at")
        ):
            continue
        return "최근 GitHub 배포 있음"
    return None


def _render_failures(bundle: IncidentBundle) -> str:
    labels = Counter(
        label
        for failure in bundle.snapshot.failures
        if (label := _FAILURE_LABELS.get(failure.collector)) is not None
    )
    if not labels:
        return "누락: 없음"
    return "누락: " + "; ".join(f"{label} 수집 실패 {count}건" for label, count in labels.items())


def _bounded_lines(lines: list[str]) -> str:
    result: list[str] = []
    for line in lines:
        candidate = "\n".join((*result, line))
        if len(candidate) > MAX_ALERT_BRIEF_CHARS:
            break
        result.append(line)
    text = "\n".join(result)
    _safe_line(text.replace("\n", " "), maximum=MAX_ALERT_BRIEF_CHARS)
    if not text:
        raise UnsafeBundleError("alert brief is empty")
    return text


def _safe_line(value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or not value.isprintable()
    ):
        raise UnsafeBundleError("alert brief contains unsafe text")
    redacted, report = Redactor().redact_text(value)
    if (
        report.replacements
        or redacted != value
        or _ACCOUNT_ID.search(value) is not None
        or _AWS_ARN.search(value) is not None
        or _SQS_URL.search(value) is not None
        or _GIT_REVISION.search(value) is not None
    ):
        raise UnsafeBundleError("alert brief contains credential-shaped text")
    return value


def _safe_identifier(value: object) -> str:
    identifier = _safe_line(value, maximum=120)
    if _DISPLAY_IDENTIFIER.fullmatch(identifier) is None:
        raise UnsafeBundleError("alert brief identifier is unsafe")
    return identifier


def _is_non_negative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
