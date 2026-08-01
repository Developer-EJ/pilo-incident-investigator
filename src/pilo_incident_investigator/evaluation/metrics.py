"""Pure scoring, paired comparison, and operating-mode gates for evaluation runs."""

from collections.abc import Iterable
from dataclasses import dataclass, replace
from decimal import Decimal
from math import fsum, isfinite
from typing import Literal, cast

from pilo_incident_investigator.agent.loop import MAX_TOTAL_TOOLS
from pilo_incident_investigator.domain import SupportedStatement, ToolResult
from pilo_incident_investigator.evaluation.schema import EvalFixture, EvalMode, EvalRun

_MODES = frozenset({"snapshot_only", "hybrid_agent"})
EVALUATION_FIXTURE_IDS = frozenset(
    {
        "alb-health-check-complete",
        "alb-health-check-noisy",
        "alb-health-check-partial",
        "composite-deploy-and-backlog",
        "deployment-regression-complete",
        "deployment-regression-noisy",
        "deployment-regression-partial",
        "ecs-oom-complete",
        "ecs-oom-noisy",
        "ecs-oom-partial",
        "external-api-rate-limit-complete",
        "external-api-rate-limit-noisy",
        "external-api-rate-limit-partial",
        "rds-secret-rotation-auth-complete",
        "rds-secret-rotation-auth-noisy",
        "rds-secret-rotation-auth-partial",
        "sqs-backlog-complete",
        "sqs-backlog-noisy",
        "sqs-backlog-partial",
        "unknown-conflicting",
        "unknown-sparse",
    }
)
UNCLASSIFIED_FIXTURE_IDS = frozenset(
    {
        "composite-deploy-and-backlog",
        "unknown-conflicting",
        "unknown-sparse",
    }
)


@dataclass(frozen=True, slots=True)
class RunMetrics:
    """Scored measurements for one fixture and one evaluation mode."""

    fixture_id: str
    mode: EvalMode
    required_evidence_recall: float
    correct_investigation_direction: bool
    unnecessary_tool_ratio: float
    unsupported_claims: int
    unsupported_statement_claims: int
    unsupported_classification_claims: int
    unclassified_applicable: bool
    unclassified_correct: bool
    tool_call_count: int
    unnecessary_tool_call_count: int
    latency_ms: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Decimal

    def __post_init__(self) -> None:
        _validate_fixture_id(self.fixture_id)
        _validate_mode(self.mode)
        _validate_ratio("required_evidence_recall", self.required_evidence_recall)
        _validate_exact_bool(
            "correct_investigation_direction", self.correct_investigation_direction
        )
        _validate_ratio("unnecessary_tool_ratio", self.unnecessary_tool_ratio)
        for name in (
            "unsupported_claims",
            "unsupported_statement_claims",
            "unsupported_classification_claims",
            "tool_call_count",
            "unnecessary_tool_call_count",
            "latency_ms",
            "input_tokens",
            "output_tokens",
        ):
            _validate_nonnegative_int(name, getattr(self, name))
        _validate_exact_bool("unclassified_applicable", self.unclassified_applicable)
        _validate_exact_bool("unclassified_correct", self.unclassified_correct)
        _validate_cost(self.estimated_cost_usd)
        if self.unsupported_claims != (
            self.unsupported_statement_claims + self.unsupported_classification_claims
        ):
            raise ValueError("unsupported claim total does not match component counts")
        if self.unnecessary_tool_call_count > self.tool_call_count:
            raise ValueError("unnecessary Tool calls cannot exceed total Tool calls")
        expected_ratio = (
            self.unnecessary_tool_call_count / self.tool_call_count if self.tool_call_count else 0.0
        )
        if self.unnecessary_tool_ratio != expected_ratio:
            raise ValueError("unnecessary Tool ratio does not match Tool call counts")
        if not self.unclassified_applicable and self.unclassified_correct:
            raise ValueError("unguarded fixtures cannot be unclassified-correct")


@dataclass(frozen=True, slots=True)
class ModeMetrics:
    """Deterministic aggregate for one side of a paired evaluation matrix."""

    mode: EvalMode
    fixture_count: int
    required_evidence_recall: float
    correct_investigation_direction_count: int
    unnecessary_tool_ratio: float
    unsupported_claims: int
    unsupported_statement_claims: int
    unsupported_classification_claims: int
    unclassified_accuracy: float
    unclassified_fixture_count: int
    unclassified_correct_count: int
    tool_call_count: int
    unnecessary_tool_call_count: int
    latency_ms: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Decimal

    def __post_init__(self) -> None:
        _validate_mode(self.mode)
        _validate_ratio("required_evidence_recall", self.required_evidence_recall)
        _validate_ratio("unnecessary_tool_ratio", self.unnecessary_tool_ratio)
        _validate_ratio("unclassified_accuracy", self.unclassified_accuracy)
        for name in (
            "fixture_count",
            "correct_investigation_direction_count",
            "unsupported_claims",
            "unsupported_statement_claims",
            "unsupported_classification_claims",
            "unclassified_fixture_count",
            "unclassified_correct_count",
            "tool_call_count",
            "unnecessary_tool_call_count",
            "latency_ms",
            "input_tokens",
            "output_tokens",
        ):
            _validate_nonnegative_int(name, getattr(self, name))
        _validate_cost(self.estimated_cost_usd)
        if self.fixture_count == 0:
            raise ValueError("mode aggregate requires at least one fixture")
        if self.correct_investigation_direction_count > self.fixture_count:
            raise ValueError("correct direction count cannot exceed fixture count")
        if self.unclassified_fixture_count > self.fixture_count:
            raise ValueError("unclassified fixture count cannot exceed fixture count")
        if self.unclassified_correct_count > self.unclassified_fixture_count:
            raise ValueError("unclassified correct count cannot exceed guarded fixture count")
        if self.unsupported_claims != (
            self.unsupported_statement_claims + self.unsupported_classification_claims
        ):
            raise ValueError("unsupported claim total does not match component counts")
        if self.unnecessary_tool_call_count > self.tool_call_count:
            raise ValueError("unnecessary Tool calls cannot exceed total Tool calls")
        expected_tool_ratio = (
            self.unnecessary_tool_call_count / self.tool_call_count if self.tool_call_count else 0.0
        )
        if self.unnecessary_tool_ratio != expected_tool_ratio:
            raise ValueError("unnecessary Tool ratio does not match Tool call counts")
        expected_unclassified_accuracy = (
            self.unclassified_correct_count / self.unclassified_fixture_count
            if self.unclassified_fixture_count
            else 1.0
        )
        if self.unclassified_accuracy != expected_unclassified_accuracy:
            raise ValueError("unclassified accuracy does not match guarded fixture counts")


@dataclass(frozen=True, slots=True)
class ComparisonMetrics:
    """Exactly paired snapshot-only and hybrid-agent aggregate metrics."""

    fixture_count: int
    snapshot_only: ModeMetrics
    hybrid_agent: ModeMetrics

    def __post_init__(self) -> None:
        _validate_nonnegative_int("fixture_count", self.fixture_count)
        if self.fixture_count == 0:
            raise ValueError("comparison requires at least one fixture")
        if self.fixture_count != 21:
            raise ValueError("comparison requires exactly 21 committed fixtures")
        if (
            type(self.snapshot_only) is not ModeMetrics
            or type(self.hybrid_agent) is not ModeMetrics
        ):
            raise TypeError("comparison sides must be exact ModeMetrics values")
        self.snapshot_only.__post_init__()
        self.hybrid_agent.__post_init__()
        if self.snapshot_only.mode != "snapshot_only":
            raise ValueError("snapshot comparison side has the wrong mode")
        if self.hybrid_agent.mode != "hybrid_agent":
            raise ValueError("hybrid comparison side has the wrong mode")
        if (
            self.snapshot_only.fixture_count != self.fixture_count
            or self.hybrid_agent.fixture_count != self.fixture_count
        ):
            raise ValueError("comparison fixture count does not match mode aggregates")
        if self.snapshot_only.unclassified_fixture_count != len(
            UNCLASSIFIED_FIXTURE_IDS
        ) or self.hybrid_agent.unclassified_fixture_count != len(UNCLASSIFIED_FIXTURE_IDS):
            raise ValueError("comparison sides must each contain exactly 3 guarded fixtures")
        if (
            self.snapshot_only.unclassified_fixture_count
            != self.hybrid_agent.unclassified_fixture_count
        ):
            raise ValueError("comparison sides have different guarded fixture counts")


def score_run(fixture: EvalFixture, run: EvalRun) -> RunMetrics:
    """Score one strict run using only fixture evidence and its expected oracle."""
    if fixture.fixture_id != run.fixture_id:
        raise ValueError("fixture ID does not match evaluation run")
    for name in ("latency_ms", "input_tokens", "output_tokens"):
        _validate_nonnegative_int(name, getattr(run, name))
    _validate_cost(run.estimated_cost_usd)

    canonical_tool_calls = tuple(result.request for result in run.investigation.tool_calls)
    if canonical_tool_calls != run.tool_calls:
        raise ValueError("Investigation Tool calls do not exactly match EvalRun Tool calls")
    if len(canonical_tool_calls) > MAX_TOTAL_TOOLS:
        raise ValueError("Investigation exceeds the Tool call budget")
    canonical_request_keys = tuple(request.deduplication_key() for request in canonical_tool_calls)
    if len(canonical_request_keys) != len(set(canonical_request_keys)):
        raise ValueError("Investigation contains a duplicate executed Tool request")
    recorded_results = _recorded_tool_results(fixture)
    for actual_result in run.investigation.tool_calls:
        recorded_result = recorded_results.get(actual_result.request.deduplication_key())
        if recorded_result is None or actual_result != replace(
            recorded_result, request=actual_result.request
        ):
            raise ValueError("Investigation contains an absent or fabricated recorded Tool result")
    available_evidence_ids = [evidence.evidence_id for evidence in fixture.snapshot.evidence]
    available_evidence_ids.extend(
        evidence.evidence_id
        for result in run.investigation.tool_calls
        for evidence in result.evidence
    )
    if len(available_evidence_ids) != len(set(available_evidence_ids)):
        raise ValueError("duplicate Evidence ID across snapshot and Tool results")
    available_ids = set(available_evidence_ids)
    statements = (*run.investigation.facts, *run.investigation.directions)
    cited_ids = {evidence_id for statement in statements for evidence_id in statement.evidence_ids}
    cited_ids.update(run.investigation.classification_evidence_ids)

    required_ids = fixture.expected.required_evidence_ids
    recall = len(required_ids & cited_ids) / len(required_ids) if required_ids else 1.0
    acceptable_directions = fixture.expected.acceptable_direction_labels
    correct_direction = bool(
        acceptable_directions
        and run.investigation.directions
        and run.investigation.directions[0].text in acceptable_directions
    )

    tool_call_count = len(canonical_tool_calls)
    unnecessary_tool_call_count = sum(
        request.tool not in fixture.expected.useful_tools for request in canonical_tool_calls
    )
    unnecessary_ratio = unnecessary_tool_call_count / tool_call_count if tool_call_count else 0.0

    unsupported_statement_claims = sum(
        _statement_is_unsupported(statement, available_ids) for statement in statements
    )
    unsupported_classification_claims = int(_classification_is_unsupported(run, available_ids))
    unclassified_applicable = fixture.expected.classification == "unclassified"
    unclassified_correct = (
        unclassified_applicable and run.investigation.classification == "unclassified"
    )

    return RunMetrics(
        fixture_id=run.fixture_id,
        mode=run.mode,
        required_evidence_recall=recall,
        correct_investigation_direction=correct_direction,
        unnecessary_tool_ratio=unnecessary_ratio,
        unsupported_claims=unsupported_statement_claims + unsupported_classification_claims,
        unsupported_statement_claims=unsupported_statement_claims,
        unsupported_classification_claims=unsupported_classification_claims,
        unclassified_applicable=unclassified_applicable,
        unclassified_correct=unclassified_correct,
        tool_call_count=tool_call_count,
        unnecessary_tool_call_count=unnecessary_tool_call_count,
        latency_ms=run.latency_ms,
        input_tokens=run.input_tokens,
        output_tokens=run.output_tokens,
        estimated_cost_usd=run.estimated_cost_usd,
    )


def compare_modes(metrics: Iterable[RunMetrics]) -> ComparisonMetrics:
    """Validate an exact paired matrix and aggregate both modes."""
    rows = tuple(metrics)
    if not rows:
        raise ValueError("cannot compare an empty metric matrix")
    if any(type(row) is not RunMetrics for row in rows):
        raise TypeError("comparison requires exact RunMetrics values")
    for row in rows:
        row.__post_init__()
        expected_unclassified_applicability = row.fixture_id in UNCLASSIFIED_FIXTURE_IDS
        if row.unclassified_applicable != expected_unclassified_applicability:
            raise ValueError("RunMetrics has incorrect unclassified applicability for its fixture")

    matrix: dict[tuple[str, EvalMode], RunMetrics] = {}
    for row in rows:
        key = (row.fixture_id, row.mode)
        if key in matrix:
            raise ValueError("duplicate fixture-mode metric row")
        matrix[key] = row

    fixture_ids = sorted({row.fixture_id for row in rows})
    if set(fixture_ids) != EVALUATION_FIXTURE_IDS or len(rows) != 42:
        raise ValueError("metric matrix must contain the exact committed 21-fixture set")
    expected_keys = {
        (fixture_id, cast(EvalMode, mode))
        for fixture_id in EVALUATION_FIXTURE_IDS
        for mode in _MODES
    }
    if set(matrix) != expected_keys:
        raise ValueError("metric matrix must contain an exact paired mode row per fixture")
    for fixture_id in fixture_ids:
        snapshot = matrix[(fixture_id, "snapshot_only")]
        hybrid = matrix[(fixture_id, "hybrid_agent")]
        if snapshot.unclassified_applicable != hybrid.unclassified_applicable:
            raise ValueError("paired rows disagree on unclassified applicability")

    snapshot_rows = tuple(matrix[(fixture_id, "snapshot_only")] for fixture_id in fixture_ids)
    hybrid_rows = tuple(matrix[(fixture_id, "hybrid_agent")] for fixture_id in fixture_ids)
    return ComparisonMetrics(
        fixture_count=len(fixture_ids),
        snapshot_only=_aggregate_mode("snapshot_only", snapshot_rows),
        hybrid_agent=_aggregate_mode("hybrid_agent", hybrid_rows),
    )


def select_operating_mode(
    comparison: ComparisonMetrics,
) -> Literal["snapshot_only", "hybrid_agent"]:
    """Select hybrid only when every safety and value gate is satisfied."""
    if type(comparison) is not ComparisonMetrics:
        raise TypeError("gate requires an exact ComparisonMetrics value")
    comparison.__post_init__()
    snapshot = comparison.snapshot_only
    hybrid = comparison.hybrid_agent
    hybrid_is_safe = (
        hybrid.unsupported_claims == 0
        and hybrid.unsupported_claims <= snapshot.unsupported_claims
        and hybrid.unclassified_accuracy >= snapshot.unclassified_accuracy
        and hybrid.required_evidence_recall >= snapshot.required_evidence_recall
        and hybrid.unnecessary_tool_ratio <= 0.25
    )
    hybrid_improves_direction = (
        hybrid.correct_investigation_direction_count
        >= snapshot.correct_investigation_direction_count + 2
    )
    return "hybrid_agent" if hybrid_is_safe and hybrid_improves_direction else "snapshot_only"


def _statement_is_unsupported(statement: SupportedStatement, available_ids: set[str]) -> bool:
    evidence_ids = statement.evidence_ids
    return (
        type(evidence_ids) is not tuple
        or not evidence_ids
        or any(
            type(evidence_id) is not str or not evidence_id.strip() for evidence_id in evidence_ids
        )
        or len(evidence_ids) != len(set(evidence_ids))
        or any(evidence_id not in available_ids for evidence_id in evidence_ids)
    )


def _recorded_tool_results(fixture: EvalFixture) -> dict[str, ToolResult]:
    recorded_results: dict[str, ToolResult] = {}
    for result in fixture.tool_results.values():
        request_key = result.request.deduplication_key()
        if request_key in recorded_results:
            raise ValueError("fixture contains a duplicate recorded Tool request")
        recorded_results[request_key] = result
    return recorded_results


def _classification_is_unsupported(run: EvalRun, available_ids: set[str]) -> bool:
    evidence_ids = run.investigation.classification_evidence_ids
    duplicate_citation = len(evidence_ids) != len(set(evidence_ids))
    unknown_citation = any(evidence_id not in available_ids for evidence_id in evidence_ids)
    missing_required_citation = (
        run.investigation.classification != "unclassified" and not evidence_ids
    )
    return duplicate_citation or unknown_citation or missing_required_citation


def _aggregate_mode(mode: EvalMode, rows: tuple[RunMetrics, ...]) -> ModeMetrics:
    fixture_count = len(rows)
    tool_call_count = sum(row.tool_call_count for row in rows)
    unnecessary_tool_call_count = sum(row.unnecessary_tool_call_count for row in rows)
    guarded_rows = tuple(row for row in rows if row.unclassified_applicable)
    return ModeMetrics(
        mode=mode,
        fixture_count=fixture_count,
        required_evidence_recall=fsum(row.required_evidence_recall for row in rows) / fixture_count,
        correct_investigation_direction_count=sum(
            row.correct_investigation_direction for row in rows
        ),
        unnecessary_tool_ratio=(
            unnecessary_tool_call_count / tool_call_count if tool_call_count else 0.0
        ),
        unsupported_claims=sum(row.unsupported_claims for row in rows),
        unsupported_statement_claims=sum(row.unsupported_statement_claims for row in rows),
        unsupported_classification_claims=sum(
            row.unsupported_classification_claims for row in rows
        ),
        unclassified_accuracy=(
            sum(row.unclassified_correct for row in guarded_rows) / len(guarded_rows)
            if guarded_rows
            else 1.0
        ),
        unclassified_fixture_count=len(guarded_rows),
        unclassified_correct_count=sum(row.unclassified_correct for row in guarded_rows),
        tool_call_count=tool_call_count,
        unnecessary_tool_call_count=unnecessary_tool_call_count,
        latency_ms=sum(row.latency_ms for row in rows),
        input_tokens=sum(row.input_tokens for row in rows),
        output_tokens=sum(row.output_tokens for row in rows),
        estimated_cost_usd=sum((row.estimated_cost_usd for row in rows), start=Decimal("0")),
    )


def _validate_fixture_id(value: str) -> None:
    if type(value) is not str or not value.strip():
        raise TypeError("fixture_id must be an exact non-empty string")


def _validate_mode(value: object) -> None:
    if type(value) is not str or value not in _MODES:
        raise TypeError("mode must be snapshot_only or hybrid_agent")


def _validate_ratio(name: str, value: float) -> None:
    if type(value) is not float:
        raise TypeError(f"{name} must be an exact float")
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be finite and between zero and one")


def _validate_nonnegative_int(name: str, value: int) -> None:
    if type(value) is not int:
        raise TypeError(f"{name} must be an exact integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _validate_exact_bool(name: str, value: bool) -> None:
    if type(value) is not bool:
        raise TypeError(f"{name} must be an exact boolean")


def _validate_cost(value: Decimal) -> None:
    if type(value) is not Decimal:
        raise TypeError("estimated_cost_usd must be an exact Decimal")
    if not value.is_finite() or value < 0:
        raise ValueError("estimated_cost_usd must be finite and non-negative")


__all__ = [
    "EVALUATION_FIXTURE_IDS",
    "UNCLASSIFIED_FIXTURE_IDS",
    "ComparisonMetrics",
    "ModeMetrics",
    "RunMetrics",
    "compare_modes",
    "score_run",
    "select_operating_mode",
]
