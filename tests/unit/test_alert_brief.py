from datetime import UTC, datetime
from pathlib import Path

import pytest

from pilo_incident_investigator.alert_brief import render_slack_alert_brief
from pilo_incident_investigator.domain import (
    AlarmEvent,
    CollectorFailure,
    Evidence,
    IncidentBundle,
    Investigation,
    JsonValue,
    Snapshot,
    SupportedStatement,
)
from pilo_incident_investigator.redaction import UnsafeBundleError
from pilo_incident_investigator.topology import Topology

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 1, 1, 2, 3, tzinfo=UTC)
ALARM_ARN = "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:pilo-dev-service-01"
SERVICE_KEY = "pilo-dev-service-01"
TARGET_GROUP = (
    "arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:"
    "targetgroup/pilo-dev-service-01/0000000000000001"
)


def _topology(*, operations: bool = True) -> Topology:
    path = (
        "config/pilo-topology.example.yaml" if operations else "tests/fixtures/topology/valid.yaml"
    )
    return Topology.load((ROOT / path).read_text(encoding="utf-8"))


def _bundle(
    *,
    evidence: tuple[Evidence, ...] = (),
    failures: tuple[CollectorFailure, ...] = (),
    alarm_name: str = SERVICE_KEY,
) -> IncidentBundle:
    return IncidentBundle(
        incident_id="inc-001",
        alarm=AlarmEvent(
            event_id="evt-001",
            alarm_arn=ALARM_ARN,
            alarm_name=alarm_name,
            state_timestamp=NOW,
            detail={},
        ),
        snapshot=Snapshot(incident_id="inc-001", evidence=evidence, failures=failures),
        investigation=Investigation(
            facts=(SupportedStatement("Agent-only fact", ("E-001",)),),
            directions=(SupportedStatement("SENSITIVE-AGENT-DIRECTION", ("E-001",)),),
            missing=("SENSITIVE-AGENT-MISSING",),
            classification="unclassified",
            tool_calls=(),
        ),
        created_at=NOW,
        metadata={"mode": "snapshot_only"},
    )


def _evidence(source: str, data: dict[str, JsonValue], *, evidence_id: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source=source,
        observed_at=NOW,
        summary="SENSITIVE-EVIDENCE-SUMMARY",
        data=data,
    )


def test_alert_brief_renders_priority_facts_owner_and_runbook() -> None:
    text = render_slack_alert_brief(
        _bundle(
            evidence=(
                _evidence(
                    "ecs.describe_services",
                    {"service": SERVICE_KEY, "desired": 2, "running": 1, "pending": 0},
                    evidence_id="E-001",
                ),
                _evidence(
                    "ecs.describe_tasks",
                    {
                        "service": SERVICE_KEY,
                        "task": "task-1",
                        "stop_code": "EssentialContainerExited",
                    },
                    evidence_id="E-002",
                ),
                _evidence(
                    "ecs.describe_tasks",
                    {
                        "service": SERVICE_KEY,
                        "task": "task-2",
                        "stop_code": "EssentialContainerExited",
                    },
                    evidence_id="E-003",
                ),
                _evidence(
                    "elbv2.describe_target_health",
                    {
                        "service": SERVICE_KEY,
                        "target_group": TARGET_GROUP,
                        "states": ["healthy", "unhealthy"],
                    },
                    evidence_id="E-004",
                ),
                _evidence(
                    "rds.describe_db_instances",
                    {"database": "pilo-dev-db-01", "status": "modifying"},
                    evidence_id="E-005",
                ),
            )
        ),
        _topology(),
    )

    assert f"[PILO][P2][ALARM] {SERVICE_KEY}" in text
    assert f"Alarm: {SERVICE_KEY}" in text
    assert "확인: running 1/2; stopped task 2건; unhealthy target 1개" in text
    assert "RDS" not in text
    assert "누락: 없음" in text
    assert "담당: API operations" in text
    assert f"Runbook: https://runbooks.example.invalid/{SERVICE_KEY}" in text
    assert "SENSITIVE-AGENT-DIRECTION" not in text
    assert "SENSITIVE-AGENT-MISSING" not in text
    assert "SENSITIVE-EVIDENCE-SUMMARY" not in text


def test_alert_brief_uses_safe_defaults_when_operations_are_absent() -> None:
    text = render_slack_alert_brief(_bundle(), _topology(operations=False))

    assert f"[PILO][P2][ALARM] {SERVICE_KEY}" in text
    assert "확인: 확인 가능한 기본 상태가 없습니다" in text
    assert "담당: 미등록" in text
    assert "Runbook: 미등록" in text


def test_alert_brief_renders_recent_deployment_presence_without_revision() -> None:
    revision = "0123456789abcdef0123456789abcdef01234567"
    text = render_slack_alert_brief(
        _bundle(
            evidence=(
                _evidence(
                    "github.deployments",
                    {
                        "repository": "synthetic-org/pilo-dev-service-01",
                        "deployment_id": "101",
                        "environment": "dev",
                        "revision": revision,
                        "created_at": "2026-08-01T01:02:03+00:00",
                    },
                    evidence_id="E-001",
                ),
            )
        ),
        _topology(),
    )

    assert "확인: 최근 GitHub 배포 있음" in text
    assert revision not in text


def test_alert_brief_uses_only_exact_snapshot_shapes_and_closed_failure_labels() -> None:
    text = render_slack_alert_brief(
        _bundle(
            evidence=(
                _evidence(
                    "logs.filter_log_events",
                    {"service": SERVICE_KEY, "message": "SENSITIVE-SERVICE-LOG"},
                    evidence_id="E-001",
                ),
                _evidence(
                    "ecs.describe_services",
                    {"service": SERVICE_KEY, "desired": 1, "running": 0, "pending": 0, "raw": "x"},
                    evidence_id="E-002",
                ),
            ),
            failures=(
                CollectorFailure("alarm_target_ecs", "timeout", "SENSITIVE-ECS-DETAIL"),
                CollectorFailure("stopped_tasks_and_logs", "timeout", "SENSITIVE-LOG-DETAIL"),
                CollectorFailure("unknown", "timeout", "SENSITIVE-UNKNOWN-DETAIL"),
            ),
        ),
        _topology(),
    )

    assert "확인: 확인 가능한 기본 상태가 없습니다" in text
    assert "누락: ECS 수집 실패 1건; 로그 수집 실패 1건" in text
    assert "SENSITIVE-" not in text


def test_alert_brief_does_not_render_an_unrelated_rds_status() -> None:
    text = render_slack_alert_brief(
        _bundle(
            evidence=(
                _evidence(
                    "rds.describe_db_instances",
                    {"database": "pilo-dev-db-08", "status": "modifying"},
                    evidence_id="E-001",
                ),
            )
        ),
        _topology(),
    )

    assert "확인: 확인 가능한 기본 상태가 없습니다" in text
    assert "RDS modifying" not in text


def test_alert_brief_is_bounded_and_never_renders_raw_task_or_agent_data() -> None:
    raw_task = "arn:aws:ecs:ap-northeast-2:000000000000:task/SENSITIVE-TASK"
    evidence = tuple(
        _evidence(
            "ecs.describe_tasks",
            {"service": SERVICE_KEY, "task": raw_task, "stop_code": "SENSITIVE-STOP-CODE"},
            evidence_id=f"E-{index:03d}",
        )
        for index in range(1, 101)
    )

    text = render_slack_alert_brief(_bundle(evidence=evidence), _topology())

    assert len(text) <= 500
    assert "stopped task 100건" in text
    assert raw_task not in text
    assert "SENSITIVE-STOP-CODE" not in text
    assert "SENSITIVE-AGENT-DIRECTION" not in text


def test_alert_brief_rejects_unsafe_publishable_alarm_values() -> None:
    with pytest.raises(UnsafeBundleError):
        render_slack_alert_brief(
            _bundle(alarm_name="authorization: bearer sensitive-credential"), _topology()
        )


@pytest.mark.parametrize(
    "alarm_name",
    [
        "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:pilo-dev-service-01",
        "000000000000",
        "https://sqs.ap-northeast-2.amazonaws.com/000000000000/pilo-dev-queue-01",
        "0123456789abcdef0123456789abcdef01234567",
    ],
)
def test_alert_brief_rejects_structural_identifiers_from_alarm_name(alarm_name: str) -> None:
    with pytest.raises(UnsafeBundleError):
        render_slack_alert_brief(_bundle(alarm_name=alarm_name), _topology())


def test_alert_brief_rejects_unapproved_target_group_and_rds_status() -> None:
    text = render_slack_alert_brief(
        _bundle(
            evidence=(
                _evidence(
                    "elbv2.describe_target_health",
                    {
                        "service": SERVICE_KEY,
                        "target_group": "not-allowlisted",
                        "states": ["unhealthy"],
                    },
                    evidence_id="E-001",
                ),
                _evidence(
                    "rds.describe_db_instances",
                    {
                        "database": "pilo-dev-db-01",
                        "status": "arn:aws:rds:ap-northeast-2:000000000000:db:synthetic",
                    },
                    evidence_id="E-002",
                ),
            )
        ),
        _topology(),
    )

    assert "확인: 확인 가능한 기본 상태가 없습니다" in text
    assert "unhealthy target" not in text
    assert "arn:aws:rds" not in text
