from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from pilo_incident_investigator.domain import (
    AlarmEvent,
    Evidence,
    IncidentBundle,
    Investigation,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)


def test_snapshot_rejects_duplicate_evidence_ids() -> None:
    evidence = Evidence(
        evidence_id="E-001",
        source="ecs.describe_services",
        observed_at=datetime(2026, 8, 1, tzinfo=UTC),
        summary="service desired=1 running=0",
        data={"desired": 1, "running": 0},
    )

    with pytest.raises(ValueError, match="duplicate Evidence ID"):
        Snapshot(incident_id="inc-123", evidence=(evidence, evidence), failures=())


def test_incident_bundle_contract_is_frozen() -> None:
    observed_at = datetime(2026, 8, 1, tzinfo=UTC)
    alarm = AlarmEvent(
        event_id="evt-001",
        alarm_arn="arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic",
        alarm_name="synthetic",
        state_timestamp=observed_at,
        detail={"state": "ALARM"},
    )
    evidence = Evidence(
        evidence_id="E-001",
        source="ecs.describe_services",
        observed_at=observed_at,
        summary="service is not running",
        data={"running": 0},
    )
    request = ToolRequest(
        tool="service_log_search",
        resource_key="service-01",
        parameters={"query": "authentication failed"},
        reason="E-001 shows the service is not running",
    )
    result = ToolResult(request=request, evidence=(evidence,), failure=None)
    statement = SupportedStatement(text="service is not running", evidence_ids=("E-001",))
    investigation = Investigation(
        facts=(statement,),
        directions=(statement,),
        missing=("stopped task reason",),
        classification="unclassified",
        tool_calls=(result,),
    )
    bundle = IncidentBundle(
        incident_id="inc-123",
        alarm=alarm,
        snapshot=Snapshot(incident_id="inc-123", evidence=(evidence,), failures=()),
        investigation=investigation,
        created_at=observed_at,
        metadata={"mode": "hybrid_agent"},
    )

    assert bundle.investigation.facts[0].evidence_ids == ("E-001",)
    with pytest.raises(FrozenInstanceError):
        bundle.incident_id = "inc-changed"  # type: ignore[misc]


def test_evidence_rejects_non_json_data() -> None:
    with pytest.raises(TypeError, match="JSON-safe"):
        Evidence(
            evidence_id="E-001",
            source="ecs.describe_services",
            observed_at=datetime(2026, 8, 1, tzinfo=UTC),
            summary="invalid payload",
            data={"invalid": object()},  # type: ignore[dict-item]
        )


def test_alarm_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        AlarmEvent(
            event_id="evt-001",
            alarm_arn="arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic",
            alarm_name="synthetic",
            state_timestamp=datetime(2026, 8, 1),
            detail={"state": "ALARM"},
        )


def test_supported_statement_requires_evidence_ids() -> None:
    with pytest.raises(ValueError, match="Evidence ID"):
        SupportedStatement(text="unsupported conclusion", evidence_ids=())


def test_bundle_rejects_mismatched_incident_id() -> None:
    observed_at = datetime(2026, 8, 1, tzinfo=UTC)
    alarm = AlarmEvent(
        event_id="evt-001",
        alarm_arn="arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic",
        alarm_name="synthetic",
        state_timestamp=observed_at,
        detail={"state": "ALARM"},
    )
    snapshot = Snapshot(incident_id="inc-snapshot", evidence=(), failures=())
    investigation = Investigation(
        facts=(),
        directions=(),
        missing=("all evidence",),
        classification="unclassified",
        tool_calls=(),
    )

    with pytest.raises(ValueError, match="incident ID"):
        IncidentBundle(
            incident_id="inc-bundle",
            alarm=alarm,
            snapshot=snapshot,
            investigation=investigation,
            created_at=observed_at,
            metadata={"mode": "snapshot_only"},
        )


def test_evidence_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Evidence(
            evidence_id="E-001",
            source="ecs.describe_services",
            observed_at=datetime(2026, 8, 1),
            summary="invalid timestamp",
            data={},
        )


def test_alarm_rejects_non_json_detail() -> None:
    with pytest.raises(TypeError, match="JSON-safe"):
        AlarmEvent(
            event_id="evt-001",
            alarm_arn="arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic",
            alarm_name="synthetic",
            state_timestamp=datetime(2026, 8, 1, tzinfo=UTC),
            detail={"invalid": object()},  # type: ignore[dict-item]
        )


def test_tool_request_rejects_non_json_parameters() -> None:
    with pytest.raises(TypeError, match="JSON-safe"):
        ToolRequest(
            tool="service_log_search",
            resource_key="service-01",
            parameters={"invalid": object()},  # type: ignore[dict-item]
            reason="inspect related logs",
        )


def test_bundle_rejects_non_json_metadata() -> None:
    observed_at = datetime(2026, 8, 1, tzinfo=UTC)
    alarm = AlarmEvent(
        event_id="evt-001",
        alarm_arn="arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic",
        alarm_name="synthetic",
        state_timestamp=observed_at,
        detail={"state": "ALARM"},
    )
    snapshot = Snapshot(incident_id="inc-123", evidence=(), failures=())
    investigation = Investigation(
        facts=(),
        directions=(),
        missing=("all evidence",),
        classification="unclassified",
        tool_calls=(),
    )

    with pytest.raises(TypeError, match="JSON-safe"):
        IncidentBundle(
            incident_id="inc-123",
            alarm=alarm,
            snapshot=snapshot,
            investigation=investigation,
            created_at=observed_at,
            metadata={"invalid": object()},  # type: ignore[dict-item]
        )
