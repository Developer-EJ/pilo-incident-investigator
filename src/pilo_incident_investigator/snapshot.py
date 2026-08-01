"""Deterministic orchestration for the mandatory baseline Snapshot."""

from dataclasses import dataclass, replace
from typing import Protocol

from pilo_incident_investigator.domain import (
    AlarmEvent,
    CollectorFailure,
    Evidence,
    Snapshot,
)
from pilo_incident_investigator.event import incident_id_for
from pilo_incident_investigator.topology import ServiceTopology, Topology

DEFAULT_COLLECTOR_NAMES = (
    "alarm_target_ecs",
    "stopped_tasks_and_logs",
    "alb_target_health",
    "all_pilo_services",
    "recent_github_deployments",
    "rds_basic_status",
)


@dataclass(frozen=True, slots=True)
class CollectionContext:
    incident_id: str
    event: AlarmEvent
    topology: Topology
    services: tuple[ServiceTopology, ...]


class Collector(Protocol):
    name: str

    def collect(self, context: CollectionContext) -> tuple[Evidence, ...]: ...


class CollectorError(RuntimeError):
    """Expected, bounded collector failure that may be preserved in a partial Snapshot."""

    def __init__(self, code: str, detail: str) -> None:
        if not code.strip() or not detail.strip():
            raise ValueError("collector failure code and detail must be non-empty")
        super().__init__("collector failed")
        self.code = code
        self.detail = detail


class SnapshotCollector:
    def __init__(self, collectors: tuple[Collector, ...]) -> None:
        names = tuple(collector.name for collector in collectors)
        if names != DEFAULT_COLLECTOR_NAMES:
            raise ValueError("collectors must match the fixed collector order")
        self._collectors = collectors

    def collect(self, event: AlarmEvent, topology: Topology) -> Snapshot:
        incident_id = incident_id_for(event.event_id)
        context = CollectionContext(
            incident_id=incident_id,
            event=event,
            topology=topology,
            services=topology.resolve_alarm(event.alarm_arn),
        )
        evidence: list[Evidence] = []
        failures: list[CollectorFailure] = []

        for collector in self._collectors:
            try:
                evidence.extend(collector.collect(context))
            except CollectorError as error:
                failures.append(
                    CollectorFailure(
                        collector=collector.name,
                        code=error.code,
                        detail=error.detail,
                    )
                )

        return Snapshot(
            incident_id=incident_id,
            evidence=_allocate_evidence_ids(evidence),
            failures=tuple(failures),
        )


def _allocate_evidence_ids(evidence: list[Evidence]) -> tuple[Evidence, ...]:
    ordered = sorted(enumerate(evidence), key=lambda item: (item[1].source, item[0]))
    return tuple(
        replace(item, evidence_id=f"E-{index:03d}")
        for index, (_, item) in enumerate(ordered, start=1)
    )
