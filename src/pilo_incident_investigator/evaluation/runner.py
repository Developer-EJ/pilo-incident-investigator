"""Deterministic paired execution for offline incident evaluation fixtures."""

from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from pilo_incident_investigator.agent.bedrock import Planner
from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.agent.loop import InvestigationAgent
from pilo_incident_investigator.agent.tools import (
    TOOL_NAMES,
    ToolDenied,
    ToolHandler,
    ToolRegistry,
)
from pilo_incident_investigator.domain import (
    Investigation,
    Snapshot,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.evaluation.schema import EvalFixture, EvalRun


class EvaluationMode(StrEnum):
    SNAPSHOT_ONLY = "snapshot_only"
    HYBRID_AGENT = "hybrid_agent"


@dataclass(frozen=True, slots=True)
class EvaluationMeasurements:
    latency_ms: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Decimal

    def __post_init__(self) -> None:
        for field_name in ("latency_ms", "input_tokens", "output_tokens"):
            value = getattr(self, field_name)
            if type(value) is not int:
                raise TypeError(f"{field_name} must be an exact integer")
            if value < 0:
                raise ValueError(f"{field_name} must be non-negative")
        if type(self.estimated_cost_usd) is not Decimal:
            raise TypeError("estimated_cost_usd must be an exact Decimal")
        if not self.estimated_cost_usd.is_finite() or self.estimated_cost_usd < 0:
            raise ValueError("estimated_cost_usd must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class RecordedEvaluation:
    """Reviewed structured model output and measurements for one fixture mode."""

    mode: EvaluationMode
    proposals: tuple[AgentProposal, ...]
    final_investigation: Investigation
    measurements: EvaluationMeasurements

    def __post_init__(self) -> None:
        if type(self.mode) is not EvaluationMode:
            raise TypeError("recorded mode must be an EvaluationMode")
        if type(self.proposals) is not tuple:
            raise TypeError("recorded proposals must be an immutable tuple")
        if any(not isinstance(item, AgentProposal) for item in self.proposals):
            raise TypeError("recorded proposals must contain AgentProposal values")
        if not isinstance(self.final_investigation, Investigation):
            raise TypeError("recorded final output must be an Investigation")
        if not isinstance(self.measurements, EvaluationMeasurements):
            raise TypeError("recorded measurements are invalid")
        if self.final_investigation.tool_calls:
            raise ValueError("recorded final output must not duplicate executed Tool results")
        if self.mode is EvaluationMode.SNAPSHOT_ONLY and self.proposals:
            raise ValueError("snapshot_only recording must not contain Tool proposals")
        if self.mode is EvaluationMode.HYBRID_AGENT and not self.proposals:
            raise ValueError("hybrid_agent recording requires a proposal sequence")


class MeasurementClock(Protocol):
    def measurements(self) -> EvaluationMeasurements: ...


class LiveEvaluationDisabled(RuntimeError):
    """Raised when live model evaluation lacks the explicit external opt-in."""


type PlannerFactory = Callable[[EvalFixture, EvaluationMode], Planner]
type ClockFactory = Callable[[EvalFixture, EvaluationMode], MeasurementClock]
type RecordingKey = tuple[str, EvaluationMode]


class RecordedPlanner:
    """Replay reviewed planner outputs without invoking a model endpoint."""

    def __init__(self, recording: RecordedEvaluation) -> None:
        self._recording = recording
        self._proposal_index = 0

    def propose(
        self,
        snapshot: Snapshot,
        prior_results: tuple[ToolResult, ...],
        remaining_budget: int,
    ) -> AgentProposal:
        del snapshot, prior_results, remaining_budget
        if self._recording.mode is not EvaluationMode.HYBRID_AGENT:
            raise RuntimeError("snapshot_only recording cannot propose Tools")
        if self._proposal_index >= len(self._recording.proposals):
            raise RuntimeError("recorded proposal sequence is exhausted")
        proposal = self._recording.proposals[self._proposal_index]
        self._proposal_index += 1
        return proposal

    def summarize(
        self,
        snapshot: Snapshot,
        tool_results: tuple[ToolResult, ...] = (),
    ) -> Investigation:
        del snapshot
        return replace(self._recording.final_investigation, tool_calls=tool_results)

    def assert_exhausted(self) -> None:
        if self._proposal_index != len(self._recording.proposals):
            raise ValueError("unconsumed recorded proposals remain after offline replay")


@dataclass(frozen=True, slots=True)
class OfflineEvaluationRunner:
    _recordings: Mapping[RecordingKey, RecordedEvaluation]

    def run_all(self, fixtures: Iterable[EvalFixture]) -> tuple[EvalRun, ...]:
        fixture_rows = tuple(fixtures)
        _validate_recording_matrix(fixture_rows, self._recordings)
        runs: list[EvalRun] = []
        for fixture in fixture_rows:
            for mode in EvaluationMode:
                recording = deepcopy(self._recordings[(fixture.fixture_id, mode)])
                planner = RecordedPlanner(recording)
                run = run_fixture(
                    fixture,
                    mode,
                    planner,
                    _RecordedMeasurementClock(recording.measurements),
                )
                planner.assert_exhausted()
                runs.append(run)
        return tuple(runs)


@dataclass(frozen=True, slots=True)
class LiveEvaluationRunner:
    _planner_factory: PlannerFactory
    _clock_factory: ClockFactory

    def run_all(self, fixtures: Iterable[EvalFixture]) -> tuple[EvalRun, ...]:
        return tuple(
            run_fixture(
                fixture,
                mode,
                self._planner_factory(fixture, mode),
                self._clock_factory(fixture, mode),
            )
            for fixture in fixtures
            for mode in EvaluationMode
        )


@dataclass(frozen=True, slots=True)
class _RecordedMeasurementClock:
    _measurements: EvaluationMeasurements

    def measurements(self) -> EvaluationMeasurements:
        return self._measurements


class _RecordedToolHandler(ToolHandler):
    def __init__(self, results: dict[str, ToolResult]) -> None:
        copied = deepcopy(tuple(results.values()))
        self._results = {result.request.deduplication_key(): result for result in copied}

    def execute(self, request: ToolRequest) -> ToolResult:
        result = self._results.get(request.deduplication_key())
        if result is None:
            raise ToolDenied("Tool request is not recorded by the fixture")
        return replace(deepcopy(result), request=deepcopy(request))


def run_fixture(
    fixture: EvalFixture,
    mode: EvaluationMode,
    planner: Planner,
    clock: MeasurementClock,
) -> EvalRun:
    """Explicit execution primitive; the default offline path uses reviewed recordings."""
    if mode is EvaluationMode.SNAPSHOT_ONLY:
        investigation = planner.summarize(fixture.snapshot, ())
        if investigation.tool_calls:
            raise ValueError("snapshot_only summary must not contain Tool calls")
    elif mode is EvaluationMode.HYBRID_AGENT:
        investigation = InvestigationAgent(planner, _fixture_registry(fixture)).run(
            fixture.snapshot, fixture.topology
        )
    else:
        raise ValueError("unknown evaluation mode")

    measurement = clock.measurements()
    if type(measurement) is not EvaluationMeasurements:
        raise TypeError("clock must return an exact EvaluationMeasurements value")
    return EvalRun(
        fixture_id=fixture.fixture_id,
        mode=mode.value,
        investigation=investigation,
        tool_calls=tuple(result.request for result in investigation.tool_calls),
        latency_ms=measurement.latency_ms,
        input_tokens=measurement.input_tokens,
        output_tokens=measurement.output_tokens,
        estimated_cost_usd=measurement.estimated_cost_usd,
    )


def build_offline_runner(
    recordings: Mapping[RecordingKey, RecordedEvaluation],
) -> OfflineEvaluationRunner:
    """Build the default network-free runner from reviewed structured recordings."""
    snapshot = deepcopy(dict(recordings))
    return OfflineEvaluationRunner(MappingProxyType(snapshot))


def build_live_runner(
    *,
    planner_factory: PlannerFactory,
    clock_factory: ClockFactory,
    allow_external: bool = False,
) -> LiveEvaluationRunner:
    """Build an injected live runner only after an explicit external-call opt-in."""
    if allow_external is not True:
        raise LiveEvaluationDisabled("live Bedrock requires explicit external opt-in")
    return LiveEvaluationRunner(planner_factory, clock_factory)


def _validate_recording_matrix(
    fixtures: tuple[EvalFixture, ...],
    recordings: Mapping[RecordingKey, RecordedEvaluation],
) -> None:
    fixture_ids = tuple(fixture.fixture_id for fixture in fixtures)
    if len(fixture_ids) != len(set(fixture_ids)):
        raise ValueError("duplicate fixture ID in offline evaluation")
    if len(fixture_ids) != 21:
        raise ValueError("offline evaluation requires exactly 21 fixtures")
    expected_keys = {(fixture_id, mode) for fixture_id in fixture_ids for mode in EvaluationMode}
    if set(recordings) != expected_keys:
        raise ValueError("recording matrix does not exactly match loaded fixtures")
    if any(recording.mode is not mode for (_, mode), recording in recordings.items()):
        raise ValueError("recording mode does not match its matrix key")


def _fixture_registry(fixture: EvalFixture) -> ToolRegistry:
    handler = _RecordedToolHandler(fixture.tool_results)
    return ToolRegistry({name: handler for name in TOOL_NAMES})
