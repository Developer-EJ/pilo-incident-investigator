"""Closed CloudWatch Embedded Metric Format rendering for Investigator operations."""

import json
import sys
import time
from collections.abc import Mapping
from typing import Literal, Protocol

type MetricName = Literal[
    "EventsReceived",
    "IncidentsPublished",
    "IncidentsDegraded",
    "IncidentsFailed",
    "CollectorFailures",
    "ProcessingDuration",
]
type MetricUnit = Literal["Count", "Milliseconds"]

_NAMESPACE = "PILO/IncidentInvestigator"
_DIMENSIONS_BY_METRIC: dict[str, frozenset[str]] = {
    "EventsReceived": frozenset({"Mode"}),
    "IncidentsPublished": frozenset({"Mode"}),
    "IncidentsDegraded": frozenset({"Stage"}),
    "IncidentsFailed": frozenset({"Stage"}),
    "CollectorFailures": frozenset({"Collector"}),
    "ProcessingDuration": frozenset({"Outcome"}),
}
_VALUES_BY_DIMENSION: dict[str, frozenset[str]] = {
    "Mode": frozenset({"snapshot_only", "hybrid_agent"}),
    "Stage": frozenset(
        {
            "parse_event",
            "load_topology",
            "claim_event",
            "snapshot",
            "investigation",
            "render",
            "publish",
        }
    ),
    "Collector": frozenset(
        {
            "alarm_target_ecs",
            "stopped_tasks_and_logs",
            "alb_target_health",
            "all_pilo_services",
            "recent_github_deployments",
            "rds_basic_status",
        }
    ),
    "Outcome": frozenset({"published", "degraded", "failed"}),
}


class MetricStream(Protocol):
    def write(self, message: str) -> int: ...


def emit_metric(
    stream: MetricStream | None = None,
    *,
    metric_name: MetricName,
    value: int,
    unit: MetricUnit,
    dimensions: Mapping[str, str],
    timestamp_ms: int | None = None,
) -> None:
    """Serialize one safe, closed-dimension EMF metric event."""
    _validate_metric(metric_name, value, unit, dimensions, timestamp_ms)
    timestamp = round(time.time() * 1_000) if timestamp_ms is None else timestamp_ms
    dimension_name = next(iter(dimensions))
    payload = {
        "_aws": {
            "Timestamp": timestamp,
            "CloudWatchMetrics": [
                {
                    "Namespace": _NAMESPACE,
                    "Dimensions": [[dimension_name]],
                    "Metrics": [{"Name": metric_name, "Unit": unit}],
                }
            ],
        },
        dimension_name: dimensions[dimension_name],
        metric_name: value,
    }
    target = sys.stdout if stream is None else stream
    target.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")


def _validate_metric(
    metric_name: str,
    value: object,
    unit: str,
    dimensions: Mapping[str, str],
    timestamp_ms: object,
) -> None:
    expected_dimensions = _DIMENSIONS_BY_METRIC.get(metric_name)
    if expected_dimensions is None or set(dimensions) != expected_dimensions:
        raise ValueError("metric dimensions are invalid")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("metric value is invalid")
    if unit != ("Milliseconds" if metric_name == "ProcessingDuration" else "Count"):
        raise ValueError("metric unit is invalid")
    dimension_name = next(iter(expected_dimensions))
    if dimensions[dimension_name] not in _VALUES_BY_DIMENSION[dimension_name]:
        raise ValueError("metric dimension value is invalid")
    if timestamp_ms is not None and (
        not isinstance(timestamp_ms, int) or isinstance(timestamp_ms, bool) or timestamp_ms < 0
    ):
        raise ValueError("metric timestamp is invalid")
