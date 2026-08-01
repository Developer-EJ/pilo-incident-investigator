import json
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.event import (
    EventValidationError,
    incident_id_for,
    parse_alarm_event,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "events" / "alarm.json"
DEV_SMOKE_FIXTURE = Path(__file__).parents[1] / "fixtures" / "events" / "dev-smoke-entry.json"


def payload() -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], json.loads(FIXTURE.read_text(encoding="utf-8")))


def test_incident_id_is_stable_and_matches_contract() -> None:
    assert incident_id_for("evt-001") == "inc-9eb19f71606879aba20e"
    assert incident_id_for("evt-001") == incident_id_for("evt-001")


def test_empty_event_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="event ID"):
        incident_id_for("")


def test_cloudwatch_alarm_event_is_normalized() -> None:
    event = parse_alarm_event(payload())

    assert event.event_id == "evt-001"
    assert event.alarm_name == "pilo-dev-service-01"
    assert event.alarm_arn.endswith(":alarm:pilo-dev-service-01")
    assert event.state_timestamp == datetime(2026, 8, 1, 1, 2, 2, tzinfo=UTC)
    assert event.detail["state"] == {
        "value": "ALARM",
        "reason": "synthetic test alarm",
        "timestamp": "2026-08-01T01:02:02Z",
    }


def test_anonymized_dev_smoke_envelope_is_accepted_by_alarm_event_boundary() -> None:
    smoke_payload = cast(
        dict[str, JsonValue], json.loads(DEV_SMOKE_FIXTURE.read_text(encoding="utf-8"))
    )

    event = parse_alarm_event(smoke_payload)

    assert smoke_payload["account"] == "000000000000"
    assert smoke_payload["region"] == "ap-northeast-2"
    assert smoke_payload["source"] == "aws.cloudwatch"
    assert smoke_payload["detail-type"] == "CloudWatch Alarm State Change"
    assert smoke_payload["time"] == "2026-08-01T02:03:04Z"
    assert smoke_payload["resources"] == [
        "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:pilo-dev-synthetic-smoke"
    ]
    assert event.event_id == "dev-smoke-event-001"
    assert event.alarm_name == "pilo-dev-synthetic-smoke"
    assert event.alarm_arn == (
        "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:pilo-dev-synthetic-smoke"
    )
    assert event.state_timestamp == datetime(2026, 8, 1, 2, 3, 3, tzinfo=UTC)
    assert event.detail["state"] == {
        "value": "ALARM",
        "reason": "synthetic smoke test",
        "timestamp": "2026-08-01T02:03:03Z",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", "aws.ecs"),
        ("detail-type", "AWS API Call via CloudTrail"),
        ("region", "us-east-1"),
    ],
)
def test_out_of_scope_event_is_rejected(field: str, value: str) -> None:
    event_payload = payload()
    event_payload[field] = value

    with pytest.raises(EventValidationError, match="unsupported event"):
        parse_alarm_event(event_payload)


def test_non_alarm_state_is_rejected() -> None:
    event_payload = payload()
    detail = cast(dict[str, JsonValue], event_payload["detail"])
    state = cast(dict[str, JsonValue], detail["state"])
    state["value"] = "OK"

    with pytest.raises(EventValidationError, match="ALARM"):
        parse_alarm_event(event_payload)


@pytest.mark.parametrize("missing", ["id", "resources", "detail"])
def test_required_event_fields_are_rejected_when_missing(missing: str) -> None:
    event_payload = payload()
    del event_payload[missing]

    with pytest.raises(EventValidationError, match="invalid alarm event"):
        parse_alarm_event(event_payload)


def test_invalid_state_timestamp_is_rejected() -> None:
    event_payload = payload()
    detail = cast(dict[str, JsonValue], event_payload["detail"])
    state = cast(dict[str, JsonValue], detail["state"])
    state["timestamp"] = "not-a-timestamp"

    with pytest.raises(EventValidationError, match="timestamp"):
        parse_alarm_event(event_payload)


def test_validation_traceback_does_not_expose_invalid_timestamp() -> None:
    sensitive_marker = "SENSITIVE-TIMESTAMP-MARKER"
    event_payload = payload()
    detail = cast(dict[str, JsonValue], event_payload["detail"])
    state = cast(dict[str, JsonValue], detail["state"])
    state["timestamp"] = sensitive_marker

    with pytest.raises(EventValidationError) as captured:
        parse_alarm_event(event_payload)

    rendered = "".join(traceback.format_exception(captured.value))
    assert sensitive_marker not in rendered


def test_validation_traceback_does_not_expose_invalid_detail_key() -> None:
    sensitive_marker = "SENSITIVE-DETAIL-KEY"
    event_payload = payload()
    detail = cast(dict[str, JsonValue], event_payload["detail"])
    detail[sensitive_marker] = cast(JsonValue, object())

    with pytest.raises(EventValidationError) as captured:
        parse_alarm_event(event_payload)

    rendered = "".join(traceback.format_exception(captured.value))
    assert sensitive_marker not in rendered


def test_multiple_alarm_resources_are_rejected() -> None:
    event_payload = payload()
    resources = cast(list[JsonValue], event_payload["resources"])
    resources.append("arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:other")

    with pytest.raises(EventValidationError, match="exactly one alarm resource"):
        parse_alarm_event(event_payload)
