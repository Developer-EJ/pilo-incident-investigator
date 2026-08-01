"""Strict types and parsing for synthetic incident evaluation fixtures."""

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from math import isfinite
from typing import Literal, cast

import yaml

from pilo_incident_investigator.agent.tools import TOOL_NAMES, ToolDenied, ToolRegistry
from pilo_incident_investigator.domain import (
    CollectorFailure,
    Evidence,
    Investigation,
    JsonValue,
    Snapshot,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.redaction import Redactor, UnsafeBundleError
from pilo_incident_investigator.topology import Topology, TopologyError

type FixtureVariant = Literal["complete", "noisy", "partial", "unknown", "composite"]
type EvalMode = Literal["snapshot_only", "hybrid_agent"]

_VARIANTS = frozenset({"complete", "noisy", "partial", "unknown", "composite"})
_MODES = frozenset({"snapshot_only", "hybrid_agent"})
_SYNTHETIC_ACCOUNT = "000000000000"
_MAX_NESTING_DEPTH = 64
_ACCOUNT_FIELDS = frozenset(
    {"account", "account_id", "accountid", "aws_account", "aws_account_id", "awsaccountid"}
)
_SAFE_TOKEN_METRIC_KEYS = frozenset({"input_tokens", "output_tokens", "token_budget"})
_BEDROCK_USAGE_METRIC_KEYS = frozenset({"inputTokens", "outputTokens", "totalTokens"})

_ACCOUNT_ID = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")


class FixtureValidationError(ValueError):
    """Raised when an evaluation fixture is malformed or unsafe to publish."""


class _ValidationOnlyHandler:
    def execute(self, request: ToolRequest) -> ToolResult:
        raise AssertionError("validation-only Tool handler must not execute")


@dataclass(frozen=True, slots=True)
class ExpectedClaim:
    text: str
    evidence_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class ToolExpectation:
    request_key: str
    tool: str
    evidence_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not self.request_key.strip():
            raise FixtureValidationError("request_key must be a non-empty string")
        if self.tool not in TOOL_NAMES:
            raise FixtureValidationError("unknown Tool")
        if not self.evidence_ids:
            raise FixtureValidationError("Tool expectation requires evidence_ids")


@dataclass(frozen=True, slots=True)
class HandoffExpectation:
    acceptable_first_direction_labels: frozenset[str]
    allowed_clarification_kinds: frozenset[str]


@dataclass(frozen=True, slots=True)
class ExpectedOutcome:
    required_evidence_ids: frozenset[str]
    acceptable_direction_labels: frozenset[str]
    useful_tools: frozenset[str]
    classification: str
    facts: tuple[ExpectedClaim, ...]
    missing_information: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvalFixture:
    fixture_id: str
    scenario: str
    variant: FixtureVariant
    alarm: dict[str, JsonValue]
    topology: Topology
    snapshot: Snapshot
    tool_results: dict[str, ToolResult]
    expected: ExpectedOutcome
    handoff: HandoffExpectation

    @classmethod
    def from_dict(cls, raw: dict[str, JsonValue]) -> "EvalFixture":
        try:
            assert_anonymous(raw)
            _require_exact_fields(
                raw,
                {
                    "fixture_id",
                    "scenario",
                    "variant",
                    "alarm",
                    "topology",
                    "snapshot",
                    "tool_results",
                    "expected",
                    "handoff",
                },
                "fixture",
            )
            fixture_id = _require_string(raw["fixture_id"], "fixture_id")
            scenario = _require_string(raw["scenario"], "scenario")
            variant = _parse_variant(raw["variant"])
            alarm = _require_mapping(raw["alarm"], "alarm")
            topology = _parse_topology(raw["topology"])
            snapshot = _parse_snapshot(raw["snapshot"])
            tool_results = _parse_tool_results(raw["tool_results"])
            _validate_tool_requests(topology, tool_results)
            expected = _parse_expected(raw["expected"])
            handoff = _parse_handoff(raw["handoff"])
            _validate_evidence_contract(snapshot, tool_results, expected)
            if variant in {"unknown", "composite"} and expected.classification != "unclassified":
                raise FixtureValidationError(
                    "unknown and composite fixtures must expect unclassified"
                )
            return cls(
                fixture_id=fixture_id,
                scenario=scenario,
                variant=variant,
                alarm=alarm,
                topology=topology,
                snapshot=snapshot,
                tool_results=tool_results,
                expected=expected,
                handoff=handoff,
            )
        except FixtureValidationError:
            raise
        except (TypeError, ValueError, TopologyError):
            raise FixtureValidationError("fixture violates a domain contract") from None


@dataclass(frozen=True, slots=True)
class EvalRun:
    fixture_id: str
    mode: EvalMode
    investigation: Investigation
    tool_calls: tuple[ToolRequest, ...]
    latency_ms: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Decimal

    def __post_init__(self) -> None:
        if not self.fixture_id.strip():
            raise FixtureValidationError("fixture_id must be a non-empty string")
        if self.mode not in _MODES:
            raise FixtureValidationError("unknown evaluation mode")
        if any(value < 0 for value in (self.latency_ms, self.input_tokens, self.output_tokens)):
            raise FixtureValidationError("evaluation measurements must be non-negative")
        if not self.estimated_cost_usd.is_finite() or self.estimated_cost_usd < 0:
            raise FixtureValidationError("estimated cost must be finite and non-negative")


def assert_anonymous(value: JsonValue) -> None:
    """Reject credential shapes and non-synthetic AWS account identifiers."""
    _walk_anonymous(value, active_containers=set())


def _walk_anonymous(
    value: JsonValue,
    parent_key: str | None = None,
    path: tuple[str | int, ...] = (),
    active_containers: set[int] | None = None,
) -> None:
    if len(path) > _MAX_NESTING_DEPTH:
        raise FixtureValidationError("maximum fixture nesting depth exceeded")
    if isinstance(value, str):
        _assert_safe_string(value)
        return
    if isinstance(value, bool):
        return
    if _is_safe_token_metric(path[:-1], parent_key, value):
        return
    account_field = (
        parent_key is not None and parent_key.lower().replace("-", "_") in _ACCOUNT_FIELDS
    )
    if isinstance(value, int) and (
        account_field or 100_000_000_000 <= abs(value) < 1_000_000_000_000
    ):
        raise FixtureValidationError("sensitive numeric account identifier is not allowed")
    if isinstance(value, float) and (
        account_field or (value.is_integer() and 100_000_000_000 <= abs(value) < 1_000_000_000_000)
    ):
        raise FixtureValidationError("sensitive numeric account identifier is not allowed")
    if isinstance(value, list):
        active = set() if active_containers is None else active_containers
        marker = id(value)
        if marker in active:
            raise FixtureValidationError("cyclic fixture structure is not allowed")
        active.add(marker)
        try:
            for index, item in enumerate(value):
                _walk_anonymous(item, parent_key, (*path, index), active)
        finally:
            active.remove(marker)
        return
    if isinstance(value, dict):
        active = set() if active_containers is None else active_containers
        marker = id(value)
        if marker in active:
            raise FixtureValidationError("cyclic fixture structure is not allowed")
        active.add(marker)
        try:
            for key, item in value.items():
                _assert_safe_string(key)
                if not (
                    _is_topology_secret_resource_path(path, key)
                    or _is_safe_token_metric(path, key, item)
                ):
                    _assert_non_sensitive_key(key)
                _walk_anonymous(item, key, (*path, key), active)
        finally:
            active.remove(marker)


def _assert_safe_string(value: str) -> None:
    account_ids = _ACCOUNT_ID.findall(value)
    if any(account_id != _SYNTHETIC_ACCOUNT for account_id in account_ids):
        raise FixtureValidationError("sensitive account identifier is not synthetic")
    if _PRIVATE_KEY.search(value):
        raise FixtureValidationError("sensitive credential shape is not allowed")
    try:
        redacted, report = Redactor().redact_text(value)
    except (RecursionError, TypeError, ValueError):
        raise FixtureValidationError("sensitive credential text is invalid") from None
    if report.replacements or redacted != value:
        raise FixtureValidationError("sensitive credential shape is not allowed")


def _assert_non_sensitive_key(value: str) -> None:
    probe: JsonValue = {value: "synthetic-evaluation-value"}
    try:
        redacted, report = Redactor().redact_json(probe)
    except UnsafeBundleError:
        raise FixtureValidationError("sensitive credential key is not allowed") from None
    if report.replacements or redacted != probe:
        raise FixtureValidationError("sensitive credential key is not allowed")


def _is_topology_secret_resource_path(path: tuple[str | int, ...], key: str) -> bool:
    return (
        key == "secrets"
        and len(path) == 3
        and path[:2] == ("topology", "services")
        and isinstance(path[2], int)
    )


def _is_safe_token_metric(
    parent_path: tuple[str | int, ...], key: str | None, value: JsonValue
) -> bool:
    return (
        (
            key in _SAFE_TOKEN_METRIC_KEYS
            or (
                key in _BEDROCK_USAGE_METRIC_KEYS
                and bool(parent_path)
                and parent_path[-1] == "usage"
            )
        )
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def _parse_topology(value: JsonValue) -> Topology:
    raw = _require_mapping(value, "topology")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise FixtureValidationError("topology version must be the integer 1")
    try:
        return Topology.load(yaml.safe_dump(raw, sort_keys=False))
    except (TypeError, yaml.YAMLError, TopologyError):
        raise FixtureValidationError("topology is invalid") from None


def _parse_snapshot(value: JsonValue) -> Snapshot:
    raw = _require_mapping(value, "snapshot")
    _require_exact_fields(raw, {"incident_id", "evidence", "failures"}, "snapshot")
    evidence = tuple(
        _parse_evidence(item, f"snapshot.evidence[{index}]")
        for index, item in enumerate(_require_list(raw["evidence"], "snapshot.evidence"))
    )
    failures = tuple(
        _parse_failure(item, f"snapshot.failures[{index}]")
        for index, item in enumerate(_require_list(raw["failures"], "snapshot.failures"))
    )
    try:
        return Snapshot(
            incident_id=_require_string(raw["incident_id"], "snapshot.incident_id"),
            evidence=evidence,
            failures=failures,
        )
    except ValueError as error:
        if "duplicate Evidence ID" in str(error):
            raise FixtureValidationError("duplicate Evidence ID") from None
        raise FixtureValidationError("snapshot violates a domain contract") from None


def _parse_evidence(value: JsonValue, path: str) -> Evidence:
    raw = _require_mapping(value, path)
    _require_exact_fields(
        raw,
        {"evidence_id", "source", "observed_at", "summary", "data"},
        path,
    )
    try:
        return Evidence(
            evidence_id=_require_string(raw["evidence_id"], f"{path}.evidence_id"),
            source=_require_string(raw["source"], f"{path}.source"),
            observed_at=_parse_datetime(raw["observed_at"], f"{path}.observed_at"),
            summary=_require_string(raw["summary"], f"{path}.summary"),
            data=_require_mapping(raw["data"], f"{path}.data"),
        )
    except FixtureValidationError:
        raise
    except (TypeError, ValueError):
        raise FixtureValidationError(f"{path} violates the Evidence contract") from None


def _parse_failure(value: JsonValue, path: str) -> CollectorFailure:
    raw = _require_mapping(value, path)
    _require_exact_fields(raw, {"collector", "code", "detail"}, path)
    return CollectorFailure(
        collector=_require_string(raw["collector"], f"{path}.collector"),
        code=_require_string(raw["code"], f"{path}.code"),
        detail=_require_string(raw["detail"], f"{path}.detail"),
    )


def _parse_tool_results(value: JsonValue) -> dict[str, ToolResult]:
    raw = _require_mapping(value, "tool_results")
    results: dict[str, ToolResult] = {}
    request_deduplication_keys: set[str] = set()
    for request_key, item in raw.items():
        if not request_key.strip():
            raise FixtureValidationError("Tool result request_key must be non-empty")
        result = _parse_tool_result(item, f"tool_results.{request_key}")
        deduplication_key = result.request.deduplication_key()
        if deduplication_key in request_deduplication_keys:
            raise FixtureValidationError("duplicate Tool request")
        request_deduplication_keys.add(deduplication_key)
        results[request_key] = result
    return results


def _validate_tool_requests(topology: Topology, tool_results: dict[str, ToolResult]) -> None:
    handler = _ValidationOnlyHandler()
    registry = ToolRegistry({name: handler for name in TOOL_NAMES})
    try:
        registry.validate_batch(
            tuple(result.request for result in tool_results.values()), topology, set()
        )
    except ToolDenied:
        raise FixtureValidationError("Tool request violates the topology allowlist") from None


def _parse_tool_result(value: JsonValue, path: str) -> ToolResult:
    raw = _require_mapping(value, path)
    _require_exact_fields(raw, {"request", "evidence", "failure"}, path)
    request = _parse_tool_request(raw["request"], f"{path}.request")
    evidence = tuple(
        _parse_evidence(item, f"{path}.evidence[{index}]")
        for index, item in enumerate(_require_list(raw["evidence"], f"{path}.evidence"))
    )
    failure_raw = raw["failure"]
    failure = None if failure_raw is None else _parse_failure(failure_raw, f"{path}.failure")
    if evidence and failure is not None:
        raise FixtureValidationError("Tool result must not contain both evidence and a failure")
    return ToolResult(request=request, evidence=evidence, failure=failure)


def _parse_tool_request(value: JsonValue, path: str) -> ToolRequest:
    raw = _require_mapping(value, path)
    _require_exact_fields(raw, {"tool", "resource_key", "parameters", "reason"}, path)
    tool = _require_string(raw["tool"], f"{path}.tool")
    if tool not in TOOL_NAMES:
        raise FixtureValidationError("unknown Tool")
    reason = _require_string(raw["reason"], f"{path}.reason")
    return ToolRequest(
        tool=tool,
        resource_key=_require_string(raw["resource_key"], f"{path}.resource_key"),
        parameters=_require_mapping(raw["parameters"], f"{path}.parameters"),
        reason=reason,
    )


def _parse_expected(value: JsonValue) -> ExpectedOutcome:
    raw = _require_mapping(value, "expected")
    _require_exact_fields(
        raw,
        {
            "required_evidence_ids",
            "acceptable_direction_labels",
            "useful_tools",
            "classification",
            "facts",
            "missing_information",
        },
        "expected",
    )
    required_evidence_ids = _string_set(
        raw["required_evidence_ids"], "expected.required_evidence_ids"
    )
    direction_labels = _string_set(
        raw["acceptable_direction_labels"],
        "expected.acceptable_direction_labels",
        require_non_empty=True,
    )
    useful_tools = _string_set(raw["useful_tools"], "expected.useful_tools")
    if not useful_tools.issubset(TOOL_NAMES):
        raise FixtureValidationError("unknown Tool")
    facts = tuple(
        _parse_expected_claim(item, f"expected.facts[{index}]")
        for index, item in enumerate(_require_list(raw["facts"], "expected.facts"))
    )
    return ExpectedOutcome(
        required_evidence_ids=required_evidence_ids,
        acceptable_direction_labels=direction_labels,
        useful_tools=useful_tools,
        classification=_require_string(raw["classification"], "expected.classification"),
        facts=facts,
        missing_information=_string_tuple(
            raw["missing_information"], "expected.missing_information"
        ),
    )


def _parse_expected_claim(value: JsonValue, path: str) -> ExpectedClaim:
    raw = _require_mapping(value, path)
    _require_exact_fields(raw, {"text", "evidence_ids"}, path)
    return ExpectedClaim(
        text=_require_string(raw["text"], f"{path}.text"),
        evidence_ids=_string_set(
            raw["evidence_ids"], f"{path}.evidence_ids", require_non_empty=True
        ),
    )


def _parse_handoff(value: JsonValue) -> HandoffExpectation:
    raw = _require_mapping(value, "handoff")
    _require_exact_fields(
        raw,
        {"acceptable_first_direction_labels", "allowed_clarification_kinds"},
        "handoff",
    )
    return HandoffExpectation(
        acceptable_first_direction_labels=_string_set(
            raw["acceptable_first_direction_labels"],
            "handoff.acceptable_first_direction_labels",
            require_non_empty=True,
        ),
        allowed_clarification_kinds=_string_set(
            raw["allowed_clarification_kinds"], "handoff.allowed_clarification_kinds"
        ),
    )


def _validate_evidence_contract(
    snapshot: Snapshot,
    tool_results: dict[str, ToolResult],
    expected: ExpectedOutcome,
) -> None:
    evidence_ids = [item.evidence_id for item in snapshot.evidence]
    evidence_ids.extend(
        item.evidence_id for result in tool_results.values() for item in result.evidence
    )
    if len(evidence_ids) != len(set(evidence_ids)):
        raise FixtureValidationError("duplicate Evidence ID")
    available = frozenset(evidence_ids)
    referenced = set(expected.required_evidence_ids)
    referenced.update(evidence_id for claim in expected.facts for evidence_id in claim.evidence_ids)
    if not referenced.issubset(available):
        raise FixtureValidationError("expected outcome references an absent Evidence ID")


def _parse_variant(value: JsonValue) -> FixtureVariant:
    variant = _require_string(value, "variant")
    if variant not in _VARIANTS:
        raise FixtureValidationError("unknown fixture variant")
    return cast(FixtureVariant, variant)


def _parse_datetime(value: JsonValue, path: str) -> datetime:
    text = _require_string(value, path)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise FixtureValidationError(f"{path} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FixtureValidationError(f"{path} must include a timezone")
    return parsed


def _require_mapping(value: object, path: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise FixtureValidationError(f"{path} must be a mapping")
    result: dict[str, JsonValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise FixtureValidationError(f"{path} must use string keys")
        result[key] = _require_json_value(item, f"{path}.{key}")
    return result


def _require_list(value: object, path: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise FixtureValidationError(f"{path} must be a list")
    return [_require_json_value(item, f"{path}[{index}]") for index, item in enumerate(value)]


def _require_json_value(value: object, path: str) -> JsonValue:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise FixtureValidationError(f"{path} must contain finite numbers")
        return value
    if isinstance(value, list):
        return _require_list(value, path)
    if isinstance(value, dict):
        return _require_mapping(value, path)
    raise FixtureValidationError(f"{path} must contain only JSON values")


def _require_string(value: JsonValue, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FixtureValidationError(f"{path} must be a non-empty string")
    return value


def _require_exact_fields(raw: dict[str, JsonValue], expected: set[str], path: str) -> None:
    unknown = set(raw) - expected
    if unknown:
        raise FixtureValidationError(f"{path} contains unknown fields")
    missing = expected - set(raw)
    if missing:
        raise FixtureValidationError(f"{path} is missing required fields")


def _string_set(value: JsonValue, path: str, *, require_non_empty: bool = False) -> frozenset[str]:
    values = _string_tuple(value, path)
    if len(values) != len(set(values)):
        raise FixtureValidationError(f"{path} must not contain duplicates")
    if require_non_empty and not values:
        raise FixtureValidationError(f"{path} must not be empty")
    return frozenset(values)


def _string_tuple(value: JsonValue, path: str) -> tuple[str, ...]:
    return tuple(
        _require_string(item, f"{path}[{index}]")
        for index, item in enumerate(_require_list(value, path))
    )
