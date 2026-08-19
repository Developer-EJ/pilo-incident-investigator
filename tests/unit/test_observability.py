import json
from typing import cast

import pytest

from pilo_incident_investigator.observability import MetricName, MetricUnit, emit_metric


class RecordingStream:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def write(self, message: str) -> int:
        self.messages.append(message)
        return len(message)


def test_emit_metric_writes_one_closed_dimension_emf_event() -> None:
    stream = RecordingStream()

    emit_metric(
        stream,
        metric_name="IncidentsFailed",
        value=1,
        unit="Count",
        dimensions={"Stage": "snapshot"},
        timestamp_ms=1_700_000_000_000,
    )

    assert stream.messages[0].endswith("\n")
    payload = json.loads(stream.messages[0])
    assert payload["Stage"] == "snapshot"
    assert payload["IncidentsFailed"] == 1
    assert payload["_aws"] == {
        "Timestamp": 1_700_000_000_000,
        "CloudWatchMetrics": [
            {
                "Namespace": "PILO/IncidentInvestigator",
                "Dimensions": [["Stage"]],
                "Metrics": [{"Name": "IncidentsFailed", "Unit": "Count"}],
            }
        ],
    }


@pytest.mark.parametrize(
    ("metric_name", "value", "unit", "dimensions"),
    [
        ("Unexpected", 1, "Count", {"Stage": "snapshot"}),
        ("IncidentsFailed", -1, "Count", {"Stage": "snapshot"}),
        ("IncidentsFailed", True, "Count", {"Stage": "snapshot"}),
        ("IncidentsFailed", 1, "Milliseconds", {"Stage": "snapshot"}),
        ("IncidentsFailed", 1, "Count", {"Stage": "raw-error"}),
        ("IncidentsFailed", 1, "Count", {"Service": "pilo-api"}),
        ("ProcessingDuration", 1, "Count", {"Outcome": "published"}),
        ("ProcessingDuration", 1, "Milliseconds", {"Outcome": "partial"}),
        ("CollectorFailures", 1, "Count", {"Collector": "unbounded"}),
    ],
)
def test_emit_metric_rejects_unknown_or_high_cardinality_values(
    metric_name: str, value: int | bool, unit: str, dimensions: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        emit_metric(
            RecordingStream(),
            metric_name=cast(MetricName, metric_name),
            value=value,
            unit=cast(MetricUnit, unit),
            dimensions=dimensions,
            timestamp_ms=1,
        )
