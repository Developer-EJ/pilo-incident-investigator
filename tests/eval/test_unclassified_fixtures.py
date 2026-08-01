import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
import yaml

from pilo_incident_investigator.agent.contracts import cites_available_evidence
from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.schema import EvalFixture, assert_anonymous
from pilo_incident_investigator.event import incident_id_for, parse_alarm_event
from pilo_incident_investigator.snapshot import _allocate_evidence_ids

REPO_ROOT = Path(__file__).parents[2]
MANIFEST_PATH = REPO_ROOT / "fixtures" / "eval" / "manifest.yaml"
GUARDED_FIXTURE_IDS = {
    "unknown-sparse",
    "unknown-conflicting",
    "composite-deploy-and-backlog",
}
EXPECTED_CONTRACTS = {
    "unknown-sparse": {
        "variant": "unknown",
        "direction": "request_missing_target_context",
        "missing": {
            "target_mapping",
            "related_logs",
            "target_health",
            "pilo_service_states",
        },
    },
    "unknown-conflicting": {
        "variant": "unknown",
        "direction": "inspect_unobserved_dependency_without_claiming_root_cause",
        "missing": {"downstream_dependency_status", "longer_log_window"},
    },
    "composite-deploy-and-backlog": {
        "variant": "composite",
        "direction": "separate_deployment_and_queue_hypotheses",
        "missing": {"causal_order_between_deploy_and_consumer_failure"},
    },
}


@pytest.fixture(scope="module")
def fixtures() -> tuple[EvalFixture, ...]:
    return load_manifest(MANIFEST_PATH)


def _guarded(fixtures: tuple[EvalFixture, ...]) -> tuple[EvalFixture, ...]:
    return tuple(item for item in fixtures if item.fixture_id in GUARDED_FIXTURE_IDS)


def _eventbridge_payload(alarm: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "version": "0",
        "id": alarm["event_id"],
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": "000000000000",
        "time": alarm["state_timestamp"],
        "region": "ap-northeast-2",
        "resources": [alarm["alarm_arn"]],
        "detail": alarm["detail"],
    }


def _nested_timestamps(value: JsonValue) -> tuple[datetime, ...]:
    timestamps: list[datetime] = []

    def visit(item: JsonValue, key: str | None = None) -> None:
        if key in {"state_timestamp", "timestamp", "created_at"}:
            if isinstance(item, int):
                timestamps.append(datetime.fromtimestamp(item / 1000, tz=UTC))
                return
            if isinstance(item, str):
                timestamps.append(datetime.fromisoformat(item.replace("Z", "+00:00")))
                return
        if isinstance(item, dict):
            for child_key, child in item.items():
                visit(child, child_key)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return tuple(timestamps)


def test_manifest_has_exactly_twenty_one_fixtures(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    assert len(fixtures) == 21


def test_unknown_and_composite_are_conservatively_unclassified(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    guarded = [item for item in fixtures if item.variant in {"unknown", "composite"}]

    assert len(guarded) == 3
    assert {item.fixture_id for item in guarded} == GUARDED_FIXTURE_IDS
    assert all(item.expected.classification == "unclassified" for item in guarded)
    assert all(item.expected.missing_information for item in guarded)


def test_guarded_fixtures_encode_the_three_approved_ambiguity_patterns(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    by_id = {item.fixture_id: item for item in _guarded(fixtures)}
    assert set(by_id) == GUARDED_FIXTURE_IDS
    for fixture_id, contract in EXPECTED_CONTRACTS.items():
        fixture = by_id[fixture_id]
        assert fixture.variant == contract["variant"]
        assert fixture.expected.acceptable_direction_labels == frozenset({contract["direction"]})
        assert fixture.handoff.acceptable_first_direction_labels == frozenset(
            {contract["direction"]}
        )
        assert set(fixture.expected.missing_information) == contract["missing"]

    sparse = by_id["unknown-sparse"]
    assert sparse.snapshot.evidence == ()
    assert sparse.expected.required_evidence_ids == frozenset()
    assert sparse.expected.facts == ()
    assert sparse.topology.resolve_alarm(str(sparse.alarm["alarm_arn"])) == ()
    assert len(sparse.snapshot.failures) == 1
    assert sparse.snapshot.failures[0].collector == "all_pilo_services"
    assert sparse.snapshot.failures[0].code == "aws_api_error"
    assert sparse.snapshot.failures[0].detail == "bounded AWS collector request failed"
    assert "pilo_service_states" in sparse.expected.missing_information

    conflicting = by_id["unknown-conflicting"]
    conflicting_required = {
        item.evidence_id: item
        for item in conflicting.snapshot.evidence
        if item.evidence_id in conflicting.expected.required_evidence_ids
    }
    assert {item.source for item in conflicting_required.values()} == {
        "logs.filter_log_events",
        "elbv2.describe_target_health",
        "github.deployments",
    }
    assert len(conflicting_required) == 3
    assert next(
        item
        for item in conflicting_required.values()
        if item.source == "elbv2.describe_target_health"
    ).data["states"] == ["healthy"]

    composite = by_id["composite-deploy-and-backlog"]
    assert {result.request.tool for result in composite.tool_results.values()} == {"sqs_status"}
    assert composite.expected.useful_tools == frozenset({"sqs_status"})
    assert {
        item.source
        for item in composite.snapshot.evidence
        if item.evidence_id in composite.expected.required_evidence_ids
    } == {
        "github.deployments",
        "logs.filter_log_events",
    }
    prior_queue_samples = [
        item
        for item in composite.snapshot.evidence
        if item.source == "logs.filter_log_events" and "visible=40" in str(item.data["message"])
    ]
    assert len(prior_queue_samples) == 1
    current_queue_samples = [
        item
        for result in composite.tool_results.values()
        for item in result.evidence
        if item.source == "sqs_status"
    ]
    assert len(current_queue_samples) == 1
    prior_queue = prior_queue_samples[0]
    current_queue = current_queue_samples[0]
    assert cast(int, prior_queue.data["timestamp"]) < int(
        current_queue.observed_at.timestamp() * 1000
    )
    assert cast(int, current_queue.data["visible"]) == 240
    assert cast(int, current_queue.data["visible"]) > 40
    assert {prior_queue.evidence_id, current_queue.evidence_id} <= (
        composite.expected.required_evidence_ids
    )
    queue_growth_facts = [
        fact
        for fact in composite.expected.facts
        if {prior_queue.evidence_id, current_queue.evidence_id} <= fact.evidence_ids
    ]
    assert len(queue_growth_facts) == 1
    assert all(token in queue_growth_facts[0].text.lower() for token in ("increased", "40", "240"))


def test_guarded_snapshot_and_tool_evidence_match_production_allocators(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in _guarded(fixtures):
        unallocated = [
            replace(item, evidence_id="collector-local") for item in fixture.snapshot.evidence
        ]
        assert fixture.snapshot.evidence == _allocate_evidence_ids(unallocated)

        snapshot_ids = {item.evidence_id for item in fixture.snapshot.evidence}
        for result in fixture.tool_results.values():
            assert cites_available_evidence(result.request.reason, snapshot_ids)
            request_hash = result.request.deduplication_key()[5:21]
            prefix = result.request.tool.replace("_", "-")
            assert [item.evidence_id for item in result.evidence] == [
                f"tool-local-{prefix}-{request_hash}-{index}"
                for index in range(1, len(result.evidence) + 1)
            ]


def test_guarded_evidence_uses_production_shapes_and_internal_order(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in _guarded(fixtures):
        logs = [
            item for item in fixture.snapshot.evidence if item.source == "logs.filter_log_events"
        ]
        assert [
            (cast(int, item.data["timestamp"]), str(item.data["message"])) for item in logs
        ] == sorted((cast(int, item.data["timestamp"]), str(item.data["message"])) for item in logs)
        all_pilo = [
            item
            for item in fixture.snapshot.evidence
            if item.source == "ecs.describe_services.all_pilo"
        ]
        if all_pilo:
            assert [item.data["service"] for item in all_pilo] == [
                service.key for service in fixture.topology.services
            ]
        for item in fixture.snapshot.evidence:
            if item.source == "ecs.describe_services":
                assert item.summary == "target ECS state"
                assert set(item.data) == {"service", "desired", "running", "pending"}
            elif item.source == "ecs.describe_services.all_pilo":
                assert item.summary == "PILO service running state"
                assert set(item.data) == {"service", "desired", "running", "pending"}
            elif item.source == "elbv2.describe_target_health":
                assert item.summary == "ALB target health"
                assert set(item.data) == {"service", "target_group", "states"}
                assert item.data["states"] == sorted(
                    str(state) for state in cast(list[JsonValue], item.data["states"])
                )
            elif item.source == "github.deployments":
                assert item.summary == "recent GitHub deployment"
                assert set(item.data) == {
                    "repository",
                    "deployment_id",
                    "environment",
                    "revision",
                    "created_at",
                }
            elif item.source == "logs.filter_log_events":
                assert item.summary == "bounded service log event"
                assert set(item.data) == {"service", "log_group", "timestamp", "message"}
            else:
                assert item.source == "rds.describe_db_instances"
                assert item.summary == "RDS basic status"
                assert set(item.data) == {"database", "status"}

        for result in fixture.tool_results.values():
            if result.request.tool == "sqs_status":
                assert len(result.evidence) == 1
                item = result.evidence[0]
                assert item.source == "sqs_status"
                assert item.summary == "SQS queue status"
                assert set(item.data) == {
                    "queue",
                    "visible",
                    "not_visible",
                    "delayed",
                    "oldest_message_age_seconds",
                }
            else:
                assert result.request.tool == "service_log_search"
                assert result.evidence == ()
                assert result.failure is not None
                assert result.failure.code == "aws_api_error"
                assert result.failure.detail == "bounded log search failed"


def test_guarded_alarms_are_unique_runtime_events_within_synthetic_window(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    event_ids: set[str] = set()
    for fixture in fixtures:
        event = parse_alarm_event(_eventbridge_payload(fixture.alarm))
        assert event.event_id not in event_ids
        event_ids.add(event.event_id)
        assert fixture.snapshot.incident_id == incident_id_for(event.event_id)

    for fixture in _guarded(fixtures):
        alarm_at = datetime.fromisoformat(
            str(fixture.alarm["state_timestamp"]).replace("Z", "+00:00")
        )
        window_start = alarm_at - timedelta(hours=1)
        evidence = tuple(fixture.snapshot.evidence) + tuple(
            item for result in fixture.tool_results.values() for item in result.evidence
        )
        assert all(window_start <= item.observed_at <= alarm_at for item in evidence)
        raw_timestamps = _nested_timestamps(fixture.alarm)
        raw_timestamps += tuple(
            timestamp for item in evidence for timestamp in _nested_timestamps(item.data)
        )
        assert raw_timestamps
        assert all(window_start <= timestamp <= alarm_at for timestamp in raw_timestamps)
        alarm_text = json.dumps(fixture.alarm).lower()
        assert fixture.scenario.lower() not in alarm_text
        assert "root cause" not in alarm_text


def test_guarded_fixtures_are_anonymous_opaque_and_observational(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    manifest = cast(dict[str, JsonValue], yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8")))
    entries = cast(list[JsonValue], manifest["fixtures"])
    guarded_paths = [
        REPO_ROOT / "fixtures" / "eval" / str(cast(dict[str, JsonValue], item)["path"])
        for item in entries
        if cast(dict[str, JsonValue], item)["fixture_id"] in GUARDED_FIXTURE_IDS
    ]
    assert len(guarded_paths) == 3
    for path in guarded_paths:
        raw = cast(JsonValue, yaml.safe_load(path.read_text(encoding="utf-8")))
        assert_anonymous(raw)

    for fixture in _guarded(fixtures):
        evidence_ids = [item.evidence_id for item in fixture.snapshot.evidence]
        evidence_ids.extend(
            item.evidence_id for result in fixture.tool_results.values() for item in result.evidence
        )
        assert all(
            re.fullmatch(r"E-\d{3}", evidence_id)
            or re.fullmatch(r"tool-local-[a-z-]+-[0-9a-f]{16}-\d+", evidence_id)
            for evidence_id in evidence_ids
        )
        assert all(
            marker not in evidence_id.lower()
            for evidence_id in evidence_ids
            for marker in ("truth", "noise", "aux", "cause")
        )
        evidence_by_id = {item.evidence_id: item for item in fixture.snapshot.evidence}
        for result in fixture.tool_results.values():
            evidence_by_id.update({item.evidence_id: item for item in result.evidence})
        assert fixture.expected.required_evidence_ids <= evidence_by_id.keys()
        fact_text = " ".join(fact.text for fact in fixture.expected.facts).lower()
        assert all(
            phrase not in fact_text
            for phrase in ("root cause", "caused", "because", "therefore", "due to")
        )
