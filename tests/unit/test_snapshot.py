import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from pilo_incident_investigator.domain import Evidence, JsonValue
from pilo_incident_investigator.event import incident_id_for, parse_alarm_event
from pilo_incident_investigator.snapshot import (
    DEFAULT_COLLECTOR_NAMES,
    CollectionContext,
    CollectorError,
    SnapshotCollector,
)
from pilo_incident_investigator.topology import Topology

FIXTURES = Path(__file__).parents[1] / "fixtures"


class FakeCollector:
    def __init__(
        self,
        name: str,
        calls: list[str],
        evidence: tuple[Evidence, ...] = (),
        contexts: list[CollectionContext] | None = None,
    ) -> None:
        self.name = name
        self._calls = calls
        self._evidence = evidence
        self._contexts = contexts

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        self._calls.append(self.name)
        if self._contexts is not None:
            self._contexts.append(context)
        return self._evidence


class FailingCollector(FakeCollector):
    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        self._calls.append(self.name)
        raise CollectorError(code="timeout", detail="bounded collector timed out")


class UnexpectedFailureCollector(FakeCollector):
    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]:
        self._calls.append(self.name)
        raise RuntimeError("programming error")


def alarm_event_payload() -> dict[str, JsonValue]:
    text = (FIXTURES / "events" / "alarm.json").read_text(encoding="utf-8")
    return cast(dict[str, JsonValue], json.loads(text))


def topology() -> Topology:
    text = (FIXTURES / "topology" / "valid.yaml").read_text(encoding="utf-8")
    return Topology.load(text)


def evidence(source: str, summary: str) -> Evidence:
    return Evidence(
        evidence_id="collector-local-id",
        source=source,
        observed_at=datetime(2026, 8, 1, tzinfo=UTC),
        summary=summary,
        data={"synthetic": True},
    )


def collectors_with(
    calls: list[str],
    overrides: Mapping[str, FakeCollector] | None = None,
) -> tuple[FakeCollector, ...]:
    selected = overrides or {}
    return tuple(selected.get(name, FakeCollector(name, calls)) for name in DEFAULT_COLLECTOR_NAMES)


def test_default_collector_names_are_fixed_and_ordered() -> None:
    assert DEFAULT_COLLECTOR_NAMES == (
        "alarm_target_ecs",
        "stopped_tasks_and_logs",
        "alb_target_health",
        "all_pilo_services",
        "recent_github_deployments",
        "rds_basic_status",
    )


def test_all_collectors_are_attempted_after_expected_failure() -> None:
    calls: list[str] = []
    overrides = {
        "alarm_target_ecs": FakeCollector(
            "alarm_target_ecs", calls, (evidence("ecs.describe_services", "running=0"),)
        ),
        "stopped_tasks_and_logs": FailingCollector("stopped_tasks_and_logs", calls),
        "alb_target_health": FakeCollector(
            "alb_target_health", calls, (evidence("elbv2.describe_target_health", "unhealthy"),)
        ),
    }

    snapshot = SnapshotCollector(collectors_with(calls, overrides)).collect(
        parse_alarm_event(alarm_event_payload()), topology()
    )

    assert calls == list(DEFAULT_COLLECTOR_NAMES)
    assert [item.evidence_id for item in snapshot.evidence] == ["E-001", "E-002"]
    assert len(snapshot.failures) == 1
    assert snapshot.failures[0].collector == "stopped_tasks_and_logs"
    assert snapshot.failures[0].code == "timeout"


def test_evidence_is_sorted_by_source_then_allocated_stable_ids() -> None:
    calls: list[str] = []
    overrides = {
        "alarm_target_ecs": FakeCollector(
            "alarm_target_ecs",
            calls,
            (
                evidence("z-source", "first z"),
                evidence("a-source", "first a"),
                evidence("a-source", "second a"),
            ),
        )
    }

    snapshot = SnapshotCollector(collectors_with(calls, overrides)).collect(
        parse_alarm_event(alarm_event_payload()), topology()
    )

    assert [(item.evidence_id, item.source, item.summary) for item in snapshot.evidence] == [
        ("E-001", "a-source", "first a"),
        ("E-002", "a-source", "second a"),
        ("E-003", "z-source", "first z"),
    ]


def test_collection_context_contains_incident_and_mapped_service() -> None:
    calls: list[str] = []
    contexts: list[CollectionContext] = []
    overrides = {"alarm_target_ecs": FakeCollector("alarm_target_ecs", calls, contexts=contexts)}
    event = parse_alarm_event(alarm_event_payload())
    loaded_topology = topology()

    snapshot = SnapshotCollector(collectors_with(calls, overrides)).collect(event, loaded_topology)

    assert snapshot.incident_id == incident_id_for(event.event_id)
    assert contexts[0].event is event
    assert contexts[0].topology is loaded_topology
    assert tuple(service.key for service in contexts[0].services) == ("pilo-dev-service-01",)


@pytest.mark.parametrize(
    "names",
    [
        DEFAULT_COLLECTOR_NAMES[:-1],
        tuple(reversed(DEFAULT_COLLECTOR_NAMES)),
    ],
)
def test_missing_or_reordered_default_collectors_are_rejected(names: tuple[str, ...]) -> None:
    calls: list[str] = []

    with pytest.raises(ValueError, match="fixed collector order"):
        SnapshotCollector(tuple(FakeCollector(name, calls) for name in names))


def test_unexpected_collector_exception_is_not_hidden() -> None:
    calls: list[str] = []
    overrides = {
        "alarm_target_ecs": UnexpectedFailureCollector("alarm_target_ecs", calls),
    }

    with pytest.raises(RuntimeError, match="programming error"):
        SnapshotCollector(collectors_with(calls, overrides)).collect(
            parse_alarm_event(alarm_event_payload()), topology()
        )

    assert calls == ["alarm_target_ecs"]
