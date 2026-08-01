from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest
import yaml

from pilo_incident_investigator.agent.tools import TOOL_NAMES
from pilo_incident_investigator.domain import (
    Investigation,
    JsonValue,
    SupportedStatement,
    ToolRequest,
)
from pilo_incident_investigator.evaluation.loader import assert_anonymous
from pilo_incident_investigator.evaluation.schema import (
    EvalFixture,
    EvalRun,
    FixtureValidationError,
    ToolExpectation,
)
from pilo_incident_investigator.topology import Topology

TOPOLOGY_PATH = Path(__file__).parents[2] / "fixtures" / "topology" / "valid.yaml"


def minimal_fixture() -> dict[str, JsonValue]:
    topology = cast(dict[str, JsonValue], yaml.safe_load(TOPOLOGY_PATH.read_text(encoding="utf-8")))
    return {
        "fixture_id": "eval-synthetic-complete",
        "scenario": "synthetic_service_failure",
        "variant": "complete",
        "alarm": {"name": "synthetic-alarm", "state": "ALARM"},
        "topology": topology,
        "snapshot": {
            "incident_id": "inc-eval-001",
            "evidence": [
                {
                    "evidence_id": "E-SNAPSHOT-1",
                    "source": "synthetic.snapshot",
                    "observed_at": "2026-01-01T00:00:00Z",
                    "summary": "synthetic service has no running task",
                    "data": {"running": 0},
                }
            ],
            "failures": [],
        },
        "tool_results": {
            "logs-for-service-01": {
                "request": {
                    "tool": "service_log_search",
                    "resource_key": "/aws/ecs/pilo-dev-service-01",
                    "parameters": {"signal": "synthetic-error"},
                    "reason": "correlate E-SNAPSHOT-1 with bounded logs",
                },
                "evidence": [
                    {
                        "evidence_id": "E-TOOL-1",
                        "source": "synthetic.tool",
                        "observed_at": "2026-01-01T00:01:00Z",
                        "summary": "synthetic bounded log observation",
                        "data": {"kind": "synthetic-error"},
                    }
                ],
                "failure": None,
            }
        },
        "expected": {
            "required_evidence_ids": ["E-SNAPSHOT-1"],
            "acceptable_direction_labels": ["inspect_service_state"],
            "useful_tools": ["service_log_search"],
            "classification": "unclassified",
            "facts": [
                {
                    "text": "the synthetic service has no running task",
                    "evidence_ids": ["E-SNAPSHOT-1"],
                }
            ],
            "missing_information": ["synthetic stopped-task reason"],
        },
        "handoff": {
            "acceptable_first_direction_labels": ["inspect_service_state"],
            "allowed_clarification_kinds": ["request_missing_evidence"],
        },
    }


def _mapping(raw: dict[str, JsonValue], key: str) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], raw[key])


def _sequence(raw: dict[str, JsonValue], key: str) -> list[JsonValue]:
    return cast(list[JsonValue], raw[key])


def test_valid_fixture_reuses_runtime_domain_contracts() -> None:
    fixture = EvalFixture.from_dict(minimal_fixture())

    assert isinstance(fixture.topology, Topology)
    assert fixture.snapshot.evidence[0].evidence_id == "E-SNAPSHOT-1"
    assert fixture.tool_results["logs-for-service-01"].request.tool in TOOL_NAMES
    assert fixture.expected.required_evidence_ids == frozenset({"E-SNAPSHOT-1"})


def test_fixture_requires_evidence_for_expected_fact() -> None:
    raw = minimal_fixture()
    expected = _mapping(raw, "expected")
    expected["facts"] = [
        {"text": "task was OOM-killed", "evidence_ids": []},
    ]

    with pytest.raises(FixtureValidationError, match="evidence_ids"):
        EvalFixture.from_dict(raw)


def test_fixture_rejects_unknown_top_level_field() -> None:
    raw = minimal_fixture()
    raw["scan_every_account"] = True

    with pytest.raises(FixtureValidationError, match="unknown fields"):
        EvalFixture.from_dict(raw)


def test_fixture_rejects_boolean_embedded_topology_version() -> None:
    raw = minimal_fixture()
    topology = _mapping(raw, "topology")
    topology["version"] = True

    with pytest.raises(FixtureValidationError, match="topology version"):
        EvalFixture.from_dict(raw)


def test_fixture_rejects_duplicate_snapshot_evidence_ids() -> None:
    raw = minimal_fixture()
    snapshot = _mapping(raw, "snapshot")
    evidence = _sequence(snapshot, "evidence")
    evidence.append(deepcopy(evidence[0]))

    with pytest.raises(FixtureValidationError, match="duplicate Evidence ID"):
        EvalFixture.from_dict(raw)


def test_fixture_rejects_evidence_id_reused_by_tool_result() -> None:
    raw = minimal_fixture()
    tool_results = _mapping(raw, "tool_results")
    result = cast(dict[str, JsonValue], tool_results["logs-for-service-01"])
    evidence = _sequence(result, "evidence")
    tool_evidence = cast(dict[str, JsonValue], evidence[0])
    tool_evidence["evidence_id"] = "E-SNAPSHOT-1"

    with pytest.raises(FixtureValidationError, match="duplicate Evidence ID"):
        EvalFixture.from_dict(raw)


def test_fixture_allows_successful_tool_result_without_evidence() -> None:
    raw = minimal_fixture()
    tool_results = _mapping(raw, "tool_results")
    result = cast(dict[str, JsonValue], tool_results["logs-for-service-01"])
    result["evidence"] = []

    fixture = EvalFixture.from_dict(raw)

    assert fixture.tool_results["logs-for-service-01"].evidence == ()
    assert fixture.tool_results["logs-for-service-01"].failure is None


@pytest.mark.parametrize("field", ["required_evidence_ids", "facts"])
def test_fixture_rejects_missing_expected_evidence_reference(field: str) -> None:
    raw = minimal_fixture()
    expected = _mapping(raw, "expected")
    if field == "required_evidence_ids":
        expected[field] = ["E-NOT-PRESENT"]
    else:
        expected[field] = [
            {"text": "unsupported synthetic claim", "evidence_ids": ["E-NOT-PRESENT"]}
        ]

    with pytest.raises(FixtureValidationError, match="absent Evidence ID"):
        EvalFixture.from_dict(raw)


@pytest.mark.parametrize("location", ["request", "expected"])
def test_fixture_rejects_unknown_tool_name(location: str) -> None:
    raw = minimal_fixture()
    if location == "request":
        tool_results = _mapping(raw, "tool_results")
        result = cast(dict[str, JsonValue], tool_results["logs-for-service-01"])
        request = _mapping(result, "request")
        request["tool"] = "scan_everything"
    else:
        expected = _mapping(raw, "expected")
        expected["useful_tools"] = ["scan_everything"]

    with pytest.raises(FixtureValidationError, match="unknown Tool"):
        EvalFixture.from_dict(raw)


def test_fixture_rejects_tool_resource_outside_parsed_topology() -> None:
    raw = minimal_fixture()
    tool_results = _mapping(raw, "tool_results")
    result = cast(dict[str, JsonValue], tool_results["logs-for-service-01"])
    request = _mapping(result, "request")
    request["resource_key"] = "/aws/ecs/not-allowlisted"

    with pytest.raises(FixtureValidationError, match="topology allowlist"):
        EvalFixture.from_dict(raw)


@pytest.mark.parametrize("variant", ["unknown", "composite"])
def test_unknown_and_composite_fixtures_must_be_unclassified(variant: str) -> None:
    raw = minimal_fixture()
    raw["variant"] = variant
    expected = _mapping(raw, "expected")
    expected["classification"] = "database_failure"

    with pytest.raises(FixtureValidationError, match="unclassified"):
        EvalFixture.from_dict(raw)


def _clear_direction_labels(raw: dict[str, JsonValue]) -> None:
    expected = _mapping(raw, "expected")
    expected["acceptable_direction_labels"] = []
    handoff = _mapping(raw, "handoff")
    handoff["acceptable_first_direction_labels"] = []


def _make_evidence_free_unknown(raw: dict[str, JsonValue]) -> None:
    raw["variant"] = "unknown"
    snapshot = _mapping(raw, "snapshot")
    snapshot["evidence"] = []
    raw["tool_results"] = {}
    expected = _mapping(raw, "expected")
    expected["required_evidence_ids"] = []
    expected["facts"] = []


def test_evidence_free_unknown_allows_no_direction_labels() -> None:
    raw = minimal_fixture()
    _make_evidence_free_unknown(raw)
    _clear_direction_labels(raw)

    fixture = EvalFixture.from_dict(raw)

    assert fixture.expected.acceptable_direction_labels == frozenset()
    assert fixture.handoff.acceptable_first_direction_labels == frozenset()


def test_unknown_with_only_tool_evidence_requires_direction_labels() -> None:
    raw = minimal_fixture()
    recorded_tool_results = raw["tool_results"]
    _make_evidence_free_unknown(raw)
    raw["tool_results"] = recorded_tool_results
    _clear_direction_labels(raw)

    with pytest.raises(FixtureValidationError, match="direction labels"):
        EvalFixture.from_dict(raw)


@pytest.mark.parametrize("variant", ["complete", "composite"])
def test_non_unknown_and_composite_require_direction_labels(variant: str) -> None:
    raw = minimal_fixture()
    raw["variant"] = variant
    _clear_direction_labels(raw)

    with pytest.raises(FixtureValidationError, match="direction labels"):
        EvalFixture.from_dict(raw)


def test_unknown_with_evidence_requires_direction_labels() -> None:
    raw = minimal_fixture()
    raw["variant"] = "unknown"
    _clear_direction_labels(raw)

    with pytest.raises(FixtureValidationError, match="direction labels"):
        EvalFixture.from_dict(raw)


@pytest.mark.parametrize("empty_side", ["expected", "handoff"])
def test_direction_label_emptiness_must_match(empty_side: str) -> None:
    raw = minimal_fixture()
    _make_evidence_free_unknown(raw)
    section = _mapping(raw, empty_side)
    field = (
        "acceptable_direction_labels"
        if empty_side == "expected"
        else "acceptable_first_direction_labels"
    )
    section[field] = []

    with pytest.raises(FixtureValidationError, match="both be empty"):
        EvalFixture.from_dict(raw)


@pytest.mark.parametrize(
    "value",
    [
        "arn:aws:rds:ap-northeast-2:123456789012:db:real-name",
        "AKIAABCDEFGHIJKLMNOP",
        "xoxb-1234567890-real-token",
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        "github_pat_11AA22BB33CC44DD55EE66FF77GG88HH99II",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_anonymity_validator_rejects_sensitive_shapes(value: str) -> None:
    with pytest.raises(FixtureValidationError, match="sensitive"):
        assert_anonymous({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        {"password": "opaque-synthetic-password"},
        {"credentials": "opaque-synthetic-credential"},
        {"message": "Authorization: Bearer opaque.synthetic.token"},
        {"message": "Basic dXNlcjpwYXNz"},
        {"message": "Bearer standalone-token-123"},
        {"message": "xapp-1-A1234567890-opaque"},
    ],
)
def test_anonymity_validator_rejects_redactor_credential_shapes(
    value: dict[str, JsonValue],
) -> None:
    with pytest.raises(FixtureValidationError, match="sensitive"):
        assert_anonymous(value)


def test_anonymity_validator_allows_exact_topology_secret_resource_path() -> None:
    assert_anonymous(minimal_fixture())


def test_anonymity_validator_allows_secret_rotation_metadata_without_values() -> None:
    assert_anonymous(
        {
            "tool": "secret_rotation_metadata",
            "resource_key": "pilo-dev-secret-01",
            "secret_rotation_metadata": {
                "rotation_enabled": True,
                "last_rotated_at": "2026-01-01T00:00:00Z",
                "version_stages": ["AWSCURRENT", "AWSPREVIOUS"],
            },
        }
    )


@pytest.mark.parametrize("key", ["input_tokens", "output_tokens", "token_budget"])
def test_anonymity_validator_allows_exact_non_negative_token_metrics(key: str) -> None:
    assert_anonymous({key: 20})
    assert_anonymous({key: 0})
    assert_anonymous({key: 123456789012})


@pytest.mark.parametrize("value", [True, -1, 1.0, "20", [], {}])
def test_anonymity_validator_rejects_non_integer_token_metric_values(
    value: JsonValue,
) -> None:
    with pytest.raises(FixtureValidationError, match="sensitive"):
        assert_anonymous({"input_tokens": value})


@pytest.mark.parametrize("key", ["token", "access_token", "auth_token"])
def test_anonymity_validator_rejects_numeric_credential_token_keys(key: str) -> None:
    with pytest.raises(FixtureValidationError, match="sensitive"):
        assert_anonymous({key: 20})


def test_anonymity_validator_allows_exact_bedrock_usage_metrics() -> None:
    assert_anonymous({"usage": {"inputTokens": 20, "outputTokens": 5, "totalTokens": 25}})


@pytest.mark.parametrize("key", ["inputTokens", "outputTokens", "totalTokens"])
def test_anonymity_validator_rejects_bedrock_metric_outside_usage(key: str) -> None:
    with pytest.raises(FixtureValidationError, match="sensitive"):
        assert_anonymous({key: 20})


@pytest.mark.parametrize("key", ["inputTokens", "outputTokens", "totalTokens"])
def test_anonymity_validator_rejects_non_integer_bedrock_usage_metric(key: str) -> None:
    with pytest.raises(FixtureValidationError, match="sensitive"):
        assert_anonymous({"usage": {key: "20"}})


def test_anonymity_validator_allows_only_synthetic_account_number() -> None:
    assert_anonymous(
        {"alarm_arn": ("arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic-alarm")}
    )

    with pytest.raises(FixtureValidationError, match="account"):
        assert_anonymous(
            {"queue_url": "https://sqs.ap-northeast-2.amazonaws.com/123456789012/real-queue"}
        )


@pytest.mark.parametrize("value", [123456789012, 123456789012.0, 1, 1.0])
def test_anonymity_validator_rejects_numeric_account_id_shapes(value: int | float) -> None:
    with pytest.raises(FixtureValidationError, match="account"):
        assert_anonymous({"account_id": value})


def test_anonymity_validator_does_not_treat_boolean_as_account_number() -> None:
    assert_anonymous({"synthetic_flag": True})


def test_anonymity_validator_rejects_excessive_nesting() -> None:
    nested: JsonValue = "leaf"
    for _ in range(70):
        nested = [nested]

    with pytest.raises(FixtureValidationError, match="nesting depth"):
        assert_anonymous(nested)


def test_anonymity_validator_rejects_cyclic_structure() -> None:
    cyclic: dict[str, JsonValue] = {}
    cyclic["self"] = cyclic

    with pytest.raises(FixtureValidationError, match="cyclic"):
        assert_anonymous(cyclic)


def test_fixture_rejects_numeric_account_id_inside_alarm() -> None:
    raw = minimal_fixture()
    alarm = _mapping(raw, "alarm")
    alarm["account_id"] = 123456789012

    with pytest.raises(FixtureValidationError, match="account"):
        EvalFixture.from_dict(raw)


def test_tool_expectation_reuses_registered_tool_names() -> None:
    expectation = ToolExpectation(
        request_key="logs-for-service-01",
        tool="service_log_search",
        evidence_ids=frozenset({"E-TOOL-1"}),
    )
    assert expectation.tool in TOOL_NAMES

    with pytest.raises(FixtureValidationError, match="unknown Tool"):
        ToolExpectation(
            request_key="unsafe",
            tool="scan_everything",
            evidence_ids=frozenset({"E-TOOL-1"}),
        )


def test_eval_run_is_frozen_and_reuses_investigation_and_tool_request() -> None:
    investigation = Investigation(
        facts=(SupportedStatement("synthetic fact", ("E-SNAPSHOT-1",)),),
        directions=(SupportedStatement("inspect service", ("E-SNAPSHOT-1",)),),
        missing=(),
        classification="unclassified",
        tool_calls=(),
    )
    request = ToolRequest(
        tool="service_log_search",
        resource_key="/aws/ecs/pilo-dev-service-01",
        parameters={},
        reason="inspect E-SNAPSHOT-1",
    )
    run = EvalRun(
        fixture_id="eval-synthetic-complete",
        mode="hybrid_agent",
        investigation=investigation,
        tool_calls=(request,),
        latency_ms=10,
        input_tokens=20,
        output_tokens=5,
        estimated_cost_usd=Decimal("0.0001"),
    )

    assert run.investigation is investigation
    assert run.tool_calls == (request,)
    with pytest.raises(FrozenInstanceError):
        run.latency_ms = 11  # type: ignore[misc]


def test_evidence_timestamp_must_be_timezone_aware() -> None:
    raw = minimal_fixture()
    snapshot = _mapping(raw, "snapshot")
    evidence = _sequence(snapshot, "evidence")
    item = cast(dict[str, JsonValue], evidence[0])
    item["observed_at"] = datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None).isoformat()

    with pytest.raises(FixtureValidationError, match="timezone"):
        EvalFixture.from_dict(raw)
