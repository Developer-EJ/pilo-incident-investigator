"""Fail-closed validation for a narrowly scoped application Alarm route change."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import NoReturn

import yaml

from pilo_incident_investigator.topology import Topology, TopologyError

BASELINE_ALARM_COUNT = 26
ADDED_ALARM_COUNT = 8
FINAL_ALARM_COUNT = 34
ADDED_SERVICE_COUNT = 4
ALARMS_PER_ADDED_SERVICE = 2
ALLOWED_TERRAFORM_ACTION_SHAPES = frozenset(
    {
        ("no-op",),
        ("create",),
        ("read",),
        ("update",),
        ("delete",),
        ("delete", "create"),
        ("create", "delete"),
        ("forget",),
        ("create", "forget"),
    }
)


class RouteContractError(ValueError):
    """Raised without embedding protected identifiers."""


class _ContractArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise RouteContractError("arguments are invalid")


def _fail(message: str) -> NoReturn:
    raise RouteContractError(message)


def _normalize_additions(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict) or len(value) != ADDED_ALARM_COUNT:
        _fail("addition count is invalid")
    normalized: dict[str, tuple[str, ...]] = {}
    for alarm_arn, service_keys in value.items():
        if (
            not isinstance(alarm_arn, str)
            or "*" in alarm_arn
            or "?" in alarm_arn
            or not isinstance(service_keys, list)
            or len(service_keys) != 1
            or not isinstance(service_keys[0], str)
        ):
            _fail("addition shape is invalid")
        normalized[alarm_arn] = (service_keys[0],)
    counts = Counter(keys[0] for keys in normalized.values())
    if len(counts) != ADDED_SERVICE_COUNT or set(counts.values()) != {ALARMS_PER_ADDED_SERVICE}:
        _fail("addition service distribution is invalid")
    return normalized


def validate_topology_transition(
    baseline_text: str, candidate_text: str, additions: object
) -> frozenset[str]:
    try:
        baseline = Topology.load(baseline_text)
        candidate = Topology.load(candidate_text)
    except TopologyError as error:
        raise RouteContractError("topology is invalid") from error
    normalized = _normalize_additions(additions)
    baseline_mappings = dict(baseline.alarm_mappings)
    candidate_mappings = dict(candidate.alarm_mappings)
    if len(baseline_mappings) != BASELINE_ALARM_COUNT:
        _fail("baseline count is invalid")
    if set(baseline_mappings) & set(normalized):
        _fail("addition overlaps baseline")
    if baseline.services != candidate.services:
        _fail("service topology changed")
    if candidate_mappings != baseline_mappings | normalized:
        _fail("candidate mapping set is invalid")
    if len(candidate_mappings) != FINAL_ALARM_COUNT:
        _fail("candidate count is invalid")
    return frozenset(candidate_mappings)


def build_candidate_topology(baseline_text: str, additions: object) -> str:
    normalized = _normalize_additions(additions)
    try:
        raw = yaml.safe_load(baseline_text)
    except yaml.YAMLError as error:
        raise RouteContractError("topology is invalid") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("alarms"), dict):
        _fail("topology is invalid")
    candidate_alarms = dict(raw["alarms"])
    candidate_alarms.update({alarm: list(keys) for alarm, keys in normalized.items()})
    raw["alarms"] = candidate_alarms
    candidate_text = yaml.safe_dump(raw, sort_keys=False)
    validate_topology_transition(baseline_text, candidate_text, additions)
    return candidate_text


def validate_event_pattern(pattern: object, expected_alarm_arns: frozenset[str]) -> None:
    expected = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "region": ["ap-northeast-2"],
        "resources": sorted(expected_alarm_arns),
        "detail": {"state": {"value": ["ALARM"]}},
    }
    if pattern != expected:
        _fail("event pattern is invalid")


def validate_terraform_plan(
    plan: object,
    baseline_alarm_arns: frozenset[str],
    candidate_alarm_arns: frozenset[str],
) -> None:
    if not isinstance(plan, dict) or plan.get("complete") is not True:
        _fail("plan is incomplete")
    raw_changes = plan.get("resource_changes")
    if not isinstance(raw_changes, list):
        _fail("plan change count is invalid")
    changes: list[dict[object, object]] = []
    for item in raw_changes:
        if not isinstance(item, dict):
            _fail("plan change entry is invalid")
        change = item.get("change")
        if not isinstance(change, dict):
            _fail("plan change entry is invalid")
        actions = change.get("actions")
        if (
            not isinstance(actions, list)
            or not all(isinstance(action, str) for action in actions)
            or tuple(actions) not in ALLOWED_TERRAFORM_ACTION_SHAPES
        ):
            _fail("plan action shape is invalid")
        if actions != ["no-op"]:
            changes.append(item)
    if len(changes) != 1:
        _fail("plan change count is invalid")
    item = changes[0]
    change = item.get("change")
    if not isinstance(change, dict) or (
        item.get("address") != "aws_cloudwatch_event_rule.alarm"
        or change.get("actions") != ["update"]
        or change.get("after_unknown") not in ({}, {"arn": True, "id": True})
    ):
        _fail("plan target is invalid")
    before_raw = change.get("before")
    after_raw = change.get("after")
    if not isinstance(before_raw, dict) or not isinstance(after_raw, dict):
        _fail("plan event pattern is invalid")
    before = dict(before_raw)
    after = dict(after_raw)
    before_event_pattern = before.pop("event_pattern", None)
    after_event_pattern = after.pop("event_pattern", None)
    if not isinstance(before_event_pattern, str) or not isinstance(after_event_pattern, str):
        _fail("plan event pattern is invalid")
    try:
        before_pattern = json.loads(before_event_pattern)
        after_pattern = json.loads(after_event_pattern)
    except json.JSONDecodeError as error:
        raise RouteContractError("plan event pattern is invalid") from error
    if before != after:
        _fail("event rule attributes changed")
    validate_event_pattern(before_pattern, baseline_alarm_arns)
    validate_event_pattern(after_pattern, candidate_alarm_arns)


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _candidate_alarms(path: Path) -> frozenset[str]:
    topology = Topology.load(path.read_text(encoding="utf-8"))
    return frozenset(alarm for alarm, _ in topology.alarm_mappings)


def run_command(args: argparse.Namespace) -> int:
    if args.command == "build-candidate":
        baseline = args.baseline.read_text(encoding="utf-8")
        additions = _read_json(args.additions)
        candidate = build_candidate_topology(baseline, additions)
        alarms = validate_topology_transition(baseline, candidate, additions)
        args.output.write_text(candidate, encoding="utf-8")
        print(len(alarms))
        return 0
    if args.command == "validate-transition":
        alarms = validate_topology_transition(
            args.baseline.read_text(encoding="utf-8"),
            args.candidate.read_text(encoding="utf-8"),
            _read_json(args.additions),
        )
        print(len(alarms))
        return 0
    if args.command == "validate-event-pattern":
        alarms = _candidate_alarms(args.candidate)
        validate_event_pattern(_read_json(args.pattern), alarms)
        print(len(alarms))
        return 0
    if args.command == "validate-plan":
        baseline_alarms = _candidate_alarms(args.baseline)
        candidate_alarms = _candidate_alarms(args.candidate)
        validate_terraform_plan(_read_json(args.plan), baseline_alarms, candidate_alarms)
        print(len(candidate_alarms))
        return 0
    _fail("command is invalid")


def _parser() -> _ContractArgumentParser:
    parser = _ContractArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-candidate")
    build.add_argument("--baseline", type=Path, required=True)
    build.add_argument("--additions", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    transition = commands.add_parser("validate-transition")
    transition.add_argument("--baseline", type=Path, required=True)
    transition.add_argument("--candidate", type=Path, required=True)
    transition.add_argument("--additions", type=Path, required=True)
    pattern = commands.add_parser("validate-event-pattern")
    pattern.add_argument("--candidate", type=Path, required=True)
    pattern.add_argument("--pattern", type=Path, required=True)
    plan = commands.add_parser("validate-plan")
    plan.add_argument("--baseline", type=Path, required=True)
    plan.add_argument("--candidate", type=Path, required=True)
    plan.add_argument("--plan", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return run_command(args)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        yaml.YAMLError,
        TopologyError,
        RouteContractError,
    ):
        print("application Alarm route validation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
