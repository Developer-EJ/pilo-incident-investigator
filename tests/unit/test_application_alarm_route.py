"""Contract tests for the fail-closed application Alarm route verifier."""

import copy
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.verify_application_alarm_route import (
    RouteContractError,
    build_candidate_topology,
    routed_alarm_arns,
    validate_event_pattern,
    validate_terraform_plan,
    validate_topology_transition,
)

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "topology" / "valid.yaml"
VERIFY = ROOT / "scripts" / "verify_application_alarm_route.py"


def synthetic_alarm(number: int) -> str:
    return f"arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic-{number:02d}"


def smoke_alarm() -> str:
    return "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic-smoke"


def baseline_topology_text(active_count: int = 26) -> str:
    topology = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    topology["alarms"] = {
        synthetic_alarm(number): [f"pilo-dev-service-{(number - 1) % 8 + 1:02d}"]
        for number in range(1, active_count + 1)
    }
    topology["alarms"][smoke_alarm()] = ["pilo-dev-service-08"]
    return yaml.safe_dump(topology, sort_keys=False)


def additions() -> dict[str, list[str]]:
    return {
        synthetic_alarm(27): ["pilo-dev-service-01"],
        synthetic_alarm(28): ["pilo-dev-service-01"],
        synthetic_alarm(29): ["pilo-dev-service-02"],
        synthetic_alarm(30): ["pilo-dev-service-02"],
        synthetic_alarm(31): ["pilo-dev-service-03"],
        synthetic_alarm(32): ["pilo-dev-service-03"],
        synthetic_alarm(33): ["pilo-dev-service-04"],
        synthetic_alarm(34): ["pilo-dev-service-04"],
    }


def candidate_topology_text() -> str:
    return build_candidate_topology(baseline_topology_text(), additions(), smoke_alarm())


def _wrong_distribution(value: dict[str, list[str]]) -> None:
    value[synthetic_alarm(34)] = ["pilo-dev-service-05"]


def _multiple_services(value: dict[str, list[str]]) -> None:
    value[synthetic_alarm(27)] = ["pilo-dev-service-01", "pilo-dev-service-02"]


def _overlap(value: dict[str, list[str]]) -> None:
    value.pop(synthetic_alarm(34))
    value[synthetic_alarm(1)] = ["pilo-dev-service-01"]


def _changed_mapping(value: dict[str, Any]) -> None:
    value["alarms"][synthetic_alarm(1)] = ["pilo-dev-service-02"]


def _extra_alarm(value: dict[str, Any]) -> None:
    value["alarms"][synthetic_alarm(35)] = ["pilo-dev-service-04"]


def _changed_service(value: dict[str, Any]) -> None:
    value["services"][0]["ecs_service"] = "synthetic-changed"


def _wildcard(value: dict[str, list[str]]) -> None:
    value[synthetic_alarm(27) + "*"] = value.pop(synthetic_alarm(27))


def event_pattern(alarms: frozenset[str]) -> dict[str, Any]:
    return {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "region": ["ap-northeast-2"],
        "resources": sorted(alarms),
        "detail": {"state": {"value": ["ALARM"]}},
    }


def terraform_plan(before_pattern: dict[str, Any], after_pattern: dict[str, Any]) -> dict[str, Any]:
    before = {"event_pattern": json.dumps(before_pattern), "name": "synthetic-rule"}
    after = {"event_pattern": json.dumps(after_pattern), "name": "synthetic-rule"}
    return {
        "complete": True,
        "resource_changes": [
            {
                "address": "aws_cloudwatch_event_rule.alarm",
                "change": {
                    "actions": ["update"],
                    "before": before,
                    "after": after,
                    "after_unknown": {"arn": True, "id": True},
                },
            }
        ],
    }


def test_candidate_is_exact_baseline_union_eight_additions() -> None:
    baseline = baseline_topology_text()
    candidate = build_candidate_topology(baseline, additions(), smoke_alarm())

    alarm_arns = validate_topology_transition(baseline, candidate, additions(), smoke_alarm())

    assert alarm_arns == frozenset(
        [*(synthetic_alarm(number) for number in range(1, 35)), smoke_alarm()]
    )
    assert routed_alarm_arns(candidate, smoke_alarm(), 35) == frozenset(
        synthetic_alarm(number) for number in range(1, 35)
    )


@pytest.mark.parametrize(
    ("baseline_count", "mutate_additions", "mutate_candidate"),
    [
        (25, None, None),
        (26, lambda value: value.pop(synthetic_alarm(34)), None),
        (26, _wrong_distribution, None),
        (
            26,
            _multiple_services,
            None,
        ),
        (
            26,
            _overlap,
            None,
        ),
        (
            26,
            None,
            _changed_mapping,
        ),
        (
            26,
            None,
            _extra_alarm,
        ),
        (
            26,
            None,
            _changed_service,
        ),
        (
            26,
            _wildcard,
            None,
        ),
    ],
    ids=[
        "baseline-count",
        "addition-count",
        "distribution",
        "multiple-services",
        "overlap",
        "mapping-change",
        "extra-alarm",
        "service-change",
        "wildcard",
    ],
)
def test_transition_rejects_any_non_exact_topology_change(
    baseline_count: int,
    mutate_additions: Callable[[dict[str, list[str]]], None] | None,
    mutate_candidate: Callable[[dict[str, Any]], None] | None,
) -> None:
    baseline = baseline_topology_text(baseline_count)
    changed_additions = additions()
    if mutate_additions is not None:
        mutate_additions(changed_additions)
    candidate = candidate_topology_text() if baseline_count == 26 else baseline
    if mutate_candidate is not None:
        data = yaml.safe_load(candidate)
        mutate_candidate(data)
        candidate = yaml.safe_dump(data, sort_keys=False)

    with pytest.raises(RouteContractError):
        validate_topology_transition(baseline, candidate, changed_additions, smoke_alarm())


def test_event_pattern_accepts_only_exact_candidate_resources() -> None:
    expected = frozenset(synthetic_alarm(number) for number in range(1, 35))

    validate_event_pattern(event_pattern(expected), expected)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["resources"].pop(),
        lambda value: value["resources"].append(synthetic_alarm(35)),
        lambda value: value["resources"].append(value["resources"][0]),
        lambda value: value["detail"]["state"]["value"].append("OK"),
        lambda value: value.update({"account": ["000000000000"]}),
        lambda value: value.update({"region": ["us-east-1"]}),
    ],
    ids=["missing", "extra", "duplicate", "ok-state", "extra-key", "wrong-region"],
)
def test_event_pattern_rejects_non_exact_pattern(mutate: Any) -> None:
    expected = frozenset(synthetic_alarm(number) for number in range(1, 35))
    pattern = event_pattern(expected)
    mutate(pattern)

    with pytest.raises(RouteContractError):
        validate_event_pattern(pattern, expected)


def test_plan_allows_only_event_rule_resource_expansion() -> None:
    baseline = frozenset(synthetic_alarm(number) for number in range(1, 27))
    candidate = frozenset(synthetic_alarm(number) for number in range(1, 35))

    validate_terraform_plan(
        terraform_plan(event_pattern(baseline), event_pattern(candidate)), baseline, candidate
    )


@pytest.mark.parametrize(
    "malformed_entry",
    [
        None,
        {"address": "synthetic.missing_change"},
        {"address": "synthetic.string_actions", "change": {"actions": "no-op"}},
        {"address": "synthetic.non_string_action", "change": {"actions": [1]}},
        {"address": "synthetic.unknown_action", "change": {"actions": ["unknown"]}},
    ],
    ids=["entry", "change", "actions-list", "actions-string", "action-shape"],
)
def test_plan_rejects_malformed_entry_even_with_valid_update(malformed_entry: object) -> None:
    baseline = frozenset(synthetic_alarm(number) for number in range(1, 27))
    candidate = frozenset(synthetic_alarm(number) for number in range(1, 35))
    plan = terraform_plan(event_pattern(baseline), event_pattern(candidate))
    plan["resource_changes"].insert(0, malformed_entry)

    with pytest.raises(RouteContractError):
        validate_terraform_plan(plan, baseline, candidate)


def test_plan_rejects_malformed_no_op_even_with_valid_update() -> None:
    baseline = frozenset(synthetic_alarm(number) for number in range(1, 27))
    candidate = frozenset(synthetic_alarm(number) for number in range(1, 35))
    plan = terraform_plan(event_pattern(baseline), event_pattern(candidate))
    plan["resource_changes"].insert(
        0,
        {
            "address": "synthetic.malformed_no_op",
            "change": {
                "actions": ["no-op"],
                "before": "malformed",
                "after": 42,
                "after_unknown": {},
            },
        },
    )

    with pytest.raises(RouteContractError):
        validate_terraform_plan(plan, baseline, candidate)


def test_plan_rejects_no_op_with_unknown_values_even_when_snapshots_match() -> None:
    baseline = frozenset(synthetic_alarm(number) for number in range(1, 27))
    candidate = frozenset(synthetic_alarm(number) for number in range(1, 35))
    plan = terraform_plan(event_pattern(baseline), event_pattern(candidate))
    snapshot = {"value": "stable"}
    plan["resource_changes"].insert(
        0,
        {
            "address": "synthetic.unknown_no_op",
            "change": {
                "actions": ["no-op"],
                "before": snapshot,
                "after": dict(snapshot),
                "after_unknown": {"value": True},
            },
        },
    )

    with pytest.raises(RouteContractError):
        validate_terraform_plan(plan, baseline, candidate)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["resource_changes"][0].update(
            {"address": "aws_lambda_function.investigator"}
        ),
        lambda value: value["resource_changes"][0]["change"].update({"actions": ["create"]}),
        lambda value: value["resource_changes"].append(copy.deepcopy(value["resource_changes"][0])),
        lambda value: value["resource_changes"][0]["change"]["after"].update({"name": "changed"}),
        lambda value: value["resource_changes"][0]["change"]["after"].update(
            {
                "event_pattern": json.dumps(
                    event_pattern(frozenset(synthetic_alarm(number) for number in range(1, 34)))
                )
            }
        ),
        lambda value: value["resource_changes"][0]["change"].update(
            {"after_unknown": {"event_pattern": True}}
        ),
    ],
    ids=[
        "lambda",
        "create",
        "second-update",
        "other-attribute",
        "wrong-resources",
        "unknown-pattern",
    ],
)
def test_plan_rejects_any_change_outside_event_pattern(mutate: Any) -> None:
    baseline = frozenset(synthetic_alarm(number) for number in range(1, 27))
    candidate = frozenset(synthetic_alarm(number) for number in range(1, 35))
    plan = terraform_plan(event_pattern(baseline), event_pattern(candidate))
    mutate(plan)

    with pytest.raises(RouteContractError):
        validate_terraform_plan(plan, baseline, candidate)


def test_cli_never_echoes_sensitive_invalid_input(tmp_path: Path) -> None:
    marker = "sensitive-marker-never-print"
    additions_file = tmp_path / "additions.json"
    baseline_file = tmp_path / "baseline.yaml"
    additions_file.write_text(json.dumps({marker: []}), encoding="utf-8")
    baseline_file.write_text(baseline_topology_text(), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY),
            "build-candidate",
            "--baseline",
            str(baseline_file),
            "--additions",
            str(additions_file),
            "--output",
            str(tmp_path / "candidate.yaml"),
            "--non-routed-alarm",
            smoke_alarm(),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert marker not in completed.stdout + completed.stderr
    assert completed.stderr == "application Alarm route validation failed\n"


def test_cli_never_echoes_sensitive_argument_parse_error() -> None:
    marker = "sensitive-argument-marker-never-print"

    completed = subprocess.run(
        [sys.executable, str(VERIFY), marker],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert marker not in completed.stdout + completed.stderr
    assert completed.stderr == "application Alarm route validation failed\n"
