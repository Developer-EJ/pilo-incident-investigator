"""Strict normalization for PILO CloudWatch Alarm EventBridge events."""

import hashlib
from datetime import datetime

from pilo_incident_investigator.domain import AlarmEvent, JsonValue

EXPECTED_SOURCE = "aws.cloudwatch"
EXPECTED_DETAIL_TYPE = "CloudWatch Alarm State Change"
EXPECTED_REGION = "ap-northeast-2"


class EventValidationError(ValueError):
    """Raised when an EventBridge payload is malformed or outside PILO scope."""


def incident_id_for(event_id: str) -> str:
    if not event_id.strip():
        raise ValueError("event ID must be a non-empty string")
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:20]
    return f"inc-{digest}"


def parse_alarm_event(payload: dict[str, JsonValue]) -> AlarmEvent:
    if (
        payload.get("source") != EXPECTED_SOURCE
        or payload.get("detail-type") != EXPECTED_DETAIL_TYPE
        or payload.get("region") != EXPECTED_REGION
    ):
        raise EventValidationError("unsupported event source, type, or region")

    try:
        event_id = _require_string(payload["id"])
        resources = payload["resources"]
        detail = payload["detail"]
    except (KeyError, TypeError) as error:
        raise EventValidationError("invalid alarm event") from error

    if not isinstance(resources, list) or len(resources) != 1:
        raise EventValidationError("event must contain exactly one alarm resource")
    alarm_arn = _require_string(resources[0])
    if not alarm_arn.startswith("arn:aws:cloudwatch:ap-northeast-2:") or ":alarm:" not in alarm_arn:
        raise EventValidationError("invalid alarm event")
    if not isinstance(detail, dict):
        raise EventValidationError("invalid alarm event")

    try:
        alarm_name = _require_string(detail["alarmName"])
        state = detail["state"]
    except (KeyError, TypeError) as error:
        raise EventValidationError("invalid alarm event") from error
    if not isinstance(state, dict):
        raise EventValidationError("invalid alarm event")
    if state.get("value") != "ALARM":
        raise EventValidationError("event state must be ALARM")
    timestamp = _parse_timestamp(state.get("timestamp"))

    try:
        return AlarmEvent(
            event_id=event_id,
            alarm_arn=alarm_arn,
            alarm_name=alarm_name,
            state_timestamp=timestamp,
            detail=dict(detail),
        )
    except (TypeError, ValueError) as error:
        raise EventValidationError("invalid alarm event") from error


def _require_string(value: JsonValue) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EventValidationError("invalid alarm event")
    return value


def _parse_timestamp(value: JsonValue | None) -> datetime:
    if not isinstance(value, str):
        raise EventValidationError("invalid state timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EventValidationError("invalid state timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventValidationError("state timestamp must include a timezone")
    return parsed
