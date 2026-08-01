"""One-way stdin-only anonymizer for the representative RDS auth fixture."""

import json
import sys
from datetime import UTC, datetime, timedelta
from typing import TextIO, cast

import yaml

from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.evaluation.schema import (
    EvalFixture,
    FixtureValidationError,
    assert_anonymous,
)

ALLOWED_RDS_SOURCE_FIELDS = frozenset(
    {
        "event_time",
        "db_status",
        "rotation_enabled",
        "last_rotated_time",
        "application_error_kind",
        "application_error_count",
    }
)

_SYNTHETIC_BASE = datetime(2026, 1, 1, tzinfo=UTC)
_MAX_WINDOW = timedelta(hours=1)
_APPLICATION_ERROR_KINDS = frozenset({"authentication_failure"})
_SYNTHETIC_ACCOUNT = "000000000000"
_SYNTHETIC_ALARM_ARN = (
    f"arn:aws:cloudwatch:ap-northeast-2:{_SYNTHETIC_ACCOUNT}:alarm:synthetic-incident-alarm"
)


def reject_unknown_keys(
    source: dict[str, JsonValue], allowed: frozenset[str] = ALLOWED_RDS_SOURCE_FIELDS
) -> None:
    if set(source) - allowed:
        raise FixtureValidationError("unknown source fields")
    if allowed - set(source):
        raise FixtureValidationError("source is missing required fields")


def anonymize(source: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Drop private shape and return one deterministic, schema-approved fixture."""
    reject_unknown_keys(source)
    event_time = _timestamp(source["event_time"], "event_time")
    last_rotated_time = _timestamp(source["last_rotated_time"], "last_rotated_time")
    if not last_rotated_time <= event_time <= last_rotated_time + _MAX_WINDOW:
        raise FixtureValidationError("rotation chronology must be within one hour")
    source_anchor = last_rotated_time
    shifted_event = _SYNTHETIC_BASE + (event_time - source_anchor)
    shifted_rotation = _SYNTHETIC_BASE + (last_rotated_time - source_anchor)

    db_status = source["db_status"]
    if db_status != "available":
        raise FixtureValidationError("db_status semantic value must be available")
    _semantic_string(
        source["application_error_kind"],
        "application_error_kind",
        _APPLICATION_ERROR_KINDS,
    )
    rotation_enabled = source["rotation_enabled"]
    if not isinstance(rotation_enabled, bool) or not rotation_enabled:
        raise FixtureValidationError("rotation_enabled must be true")
    application_error_count = source["application_error_count"]
    if (
        isinstance(application_error_count, bool)
        or not isinstance(application_error_count, int)
        or application_error_count < 1
    ):
        raise FixtureValidationError("application_error_count must be a positive integer")

    result = _build_complete_fixture(
        shifted_event=shifted_event,
        shifted_rotation=shifted_rotation,
        db_status=db_status,
        rotation_enabled=rotation_enabled,
        application_error_count=application_error_count,
    )
    assert_anonymous(result)
    EvalFixture.from_dict(result)
    return result


def _timestamp(value: JsonValue, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise FixtureValidationError(f"{field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FixtureValidationError(f"{field} must be a timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FixtureValidationError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _semantic_string(value: JsonValue, field: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise FixtureValidationError(f"{field} is not an approved semantic value")
    return value


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _alarm(state_timestamp: datetime, application_error_count: int) -> dict[str, JsonValue]:
    state_text = _iso(state_timestamp)
    return {
        "event_id": "evt-001",
        "alarm_arn": _SYNTHETIC_ALARM_ARN,
        "alarm_name": "synthetic-incident-alarm",
        "state_timestamp": state_text,
        "detail": {
            "alarmName": "synthetic-incident-alarm",
            "state": {
                "value": "ALARM",
                "reason": f"synthetic threshold breached: {application_error_count} >= 5",
                "timestamp": state_text,
            },
            "previousState": {
                "value": "OK",
                "reason": "synthetic metric within threshold",
                "timestamp": _iso(state_timestamp - timedelta(minutes=1)),
            },
            "configuration": {
                "metrics": [
                    {
                        "id": "m1",
                        "metricStat": {
                            "metric": {
                                "namespace": "PILO/Synthetic",
                                "name": "AuthenticationErrorCount",
                                "dimensions": {
                                    "ClusterName": "pilo-dev-cluster",
                                    "ServiceName": "pilo-dev-service-01",
                                },
                            },
                            "period": 60,
                            "stat": "Average",
                        },
                        "returnData": True,
                    }
                ]
            },
        },
    }


def _topology() -> dict[str, JsonValue]:
    services: list[JsonValue] = []
    for index in range(1, 9):
        suffix = f"{index:02d}"
        services.append(
            {
                "key": f"pilo-dev-service-{suffix}",
                "ecs_cluster": "pilo-dev-cluster",
                "ecs_service": f"pilo-dev-service-{suffix}",
                "log_groups": [f"/aws/ecs/pilo-dev-service-{suffix}"],
                "target_groups": [f"pilo-dev-target-{suffix}"],
                "rds_instances": [f"pilo-dev-db-{suffix}"],
                "secrets": [f"pilo-dev-secret-{suffix}"],
                "queues": [
                    "https://sqs.ap-northeast-2.amazonaws.com/"
                    f"{_SYNTHETIC_ACCOUNT}/pilo-dev-queue-{suffix}"
                ],
                "github_repository": f"synthetic-org/pilo-dev-service-{suffix}",
            }
        )
    return {
        "version": 1,
        "environment": "dev",
        "region": "ap-northeast-2",
        "services": services,
        "alarms": {_SYNTHETIC_ALARM_ARN: ["pilo-dev-service-01"]},
    }


def _evidence(
    evidence_id: str,
    source: str,
    observed_at: datetime,
    summary: str,
    data: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    return {
        "evidence_id": evidence_id,
        "source": source,
        "observed_at": _iso(observed_at),
        "summary": summary,
        "data": data,
    }


def _request(tool: str, resource_key: str) -> dict[str, JsonValue]:
    return {
        "tool": tool,
        "resource_key": resource_key,
        "parameters": {},
        "reason": "E-001 supports this bounded read-only lookup.",
    }


def _allocate_snapshot_ids(
    evidence: list[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    def source_order(entry: tuple[int, dict[str, JsonValue]]) -> tuple[str, int]:
        source = entry[1]["source"]
        if not isinstance(source, str):
            raise FixtureValidationError("evidence source must be a string")
        return source, entry[0]

    ordered = sorted(enumerate(evidence), key=source_order)
    result: list[dict[str, JsonValue]] = []
    for index, (_, item) in enumerate(ordered, start=1):
        item["evidence_id"] = f"E-{index:03d}"
        result.append(item)
    return result


def _build_complete_fixture(
    *,
    shifted_event: datetime,
    shifted_rotation: datetime,
    db_status: str,
    rotation_enabled: bool,
    application_error_count: int,
) -> dict[str, JsonValue]:
    evidence: list[dict[str, JsonValue]] = [
        _evidence(
            "E-001",
            "ecs.describe_services",
            shifted_event,
            "target ECS state",
            {
                "service": "pilo-dev-service-01",
                "desired": 1,
                "running": 1,
                "pending": 0,
            },
        ),
        _evidence(
            "E-APP-AUTH-ERROR",
            "logs.filter_log_events",
            shifted_event,
            "bounded service log event",
            {
                "service": "pilo-dev-service-01",
                "log_group": "/aws/ecs/pilo-dev-service-01",
                "timestamp": int(shifted_event.timestamp() * 1000),
                "message": (
                    f"synthetic authentication failure repeated {application_error_count} times"
                ),
            },
        ),
        _evidence(
            "E-010",
            "elbv2.describe_target_health",
            shifted_event,
            "ALB target health",
            {
                "service": "pilo-dev-service-01",
                "target_group": "pilo-dev-target-01",
                "states": ["healthy"],
            },
        ),
    ]
    for index in range(1, 9):
        evidence.append(
            _evidence(
                f"E-{19 + index:03d}",
                "ecs.describe_services.all_pilo",
                shifted_event,
                "PILO service running state",
                {
                    "service": f"pilo-dev-service-{index:02d}",
                    "desired": 1,
                    "running": 1,
                    "pending": 0,
                },
            )
        )
    evidence.extend(
        [
            _evidence(
                "E-030",
                "github.deployments",
                shifted_event,
                "recent GitHub deployment",
                {
                    "repository": "synthetic-org/pilo-dev-service-01",
                    "deployment_id": "1001",
                    "environment": "dev",
                    "revision": "1" * 40,
                    "created_at": (shifted_event - timedelta(minutes=1))
                    .astimezone(UTC)
                    .isoformat(),
                },
            ),
            _evidence(
                "E-RDS-STATUS",
                "rds.describe_db_instances",
                shifted_event,
                "RDS basic status",
                {"database": "pilo-dev-db-01", "status": db_status},
            ),
        ]
    )
    evidence = _allocate_snapshot_ids(evidence)
    evidence_values: list[JsonValue] = [item for item in evidence]
    tool_results: dict[str, JsonValue] = {
        "secret-rotation-metadata": {
            "request": _request("secret_rotation_metadata", "pilo-dev-secret-01"),
            "evidence": [
                _evidence(
                    "tool-local-secret-rotation-metadata-898a9bd50e9b53b7-1",
                    "secret_rotation_metadata",
                    shifted_event,
                    "secret rotation metadata",
                    {
                        "rotation_enabled": rotation_enabled,
                        "last_rotated_at": shifted_rotation.astimezone(UTC).isoformat(),
                        "last_changed_at": shifted_rotation.astimezone(UTC).isoformat(),
                        "version_stages": ["AWSCURRENT", "AWSPREVIOUS"],
                    },
                )
            ],
            "failure": None,
        },
        "rds-events": {
            "request": _request("rds_events", "pilo-dev-db-01"),
            "evidence": [
                _evidence(
                    "tool-local-rds-events-9723d7365c163419-1",
                    "rds_events",
                    shifted_event,
                    "RDS event",
                    {
                        "database": "pilo-dev-db-01",
                        "occurred_at": shifted_event.astimezone(UTC).isoformat(),
                        "message": "synthetic database connection authentication event",
                    },
                )
            ],
            "failure": None,
        },
        "service-log-search": {
            "request": _request("service_log_search", "/aws/ecs/pilo-dev-service-01"),
            "evidence": [
                _evidence(
                    "tool-local-service-log-search-ba1bcdf6a405dd96-1",
                    "service_log_search",
                    shifted_event,
                    "service log event",
                    {
                        "log_group": "/aws/ecs/pilo-dev-service-01",
                        "timestamp": int(shifted_event.timestamp() * 1000),
                        "message": (
                            "synthetic authentication failure repeated "
                            f"{application_error_count} times"
                        ),
                        "log_stream": "synthetic/service-01/auth",
                    },
                )
            ],
            "failure": None,
        },
    }
    return {
        "fixture_id": "rds-secret-rotation-auth-complete",
        "scenario": "rds_secret_rotation_auth",
        "variant": "complete",
        "alarm": _alarm(shifted_event, application_error_count),
        "topology": _topology(),
        "snapshot": {
            "incident_id": "inc-9eb19f71606879aba20e",
            "evidence": evidence_values,
            "failures": [],
        },
        "tool_results": tool_results,
        "expected": {
            "required_evidence_ids": [
                "E-013",
                "E-012",
                "tool-local-secret-rotation-metadata-898a9bd50e9b53b7-1",
            ],
            "acceptable_direction_labels": ["correlate_rotation_time_with_auth_failures"],
            "useful_tools": [
                "secret_rotation_metadata",
                "rds_events",
                "service_log_search",
            ],
            "classification": "rds_auth_failure",
            "facts": [
                {
                    "text": "synthetic authentication failures correlate with rotation metadata",
                    "evidence_ids": [
                        "E-013",
                        "E-012",
                        "tool-local-secret-rotation-metadata-898a9bd50e9b53b7-1",
                    ],
                }
            ],
            "missing_information": [],
        },
        "handoff": {
            "acceptable_first_direction_labels": ["correlate_rotation_time_with_auth_failures"],
            "allowed_clarification_kinds": [],
        },
    }


def _reject_json_constant(_: str) -> JsonValue:
    raise ValueError


def _reject_duplicate_object(
    pairs: list[tuple[str, JsonValue]],
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        stderr.write("input must be provided as JSON on stdin\n")
        return 2
    try:
        parsed = json.loads(
            stdin.read(),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_object,
        )
        if not isinstance(parsed, dict) or any(not isinstance(key, str) for key in parsed):
            raise FixtureValidationError("source must be a mapping")
        source = cast(dict[str, JsonValue], parsed)
        result = anonymize(source)
        rendered = yaml.safe_dump(result, sort_keys=False, allow_unicode=True)
    except (FixtureValidationError, UnicodeError, ValueError, yaml.YAMLError):
        stderr.write("invalid source input\n")
        return 2
    stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
