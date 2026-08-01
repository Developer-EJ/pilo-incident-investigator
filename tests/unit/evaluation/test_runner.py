from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.domain import (
    Investigation,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.runner import (
    EvaluationMeasurements,
    EvaluationMode,
    LiveEvaluationDisabled,
    RecordedEvaluation,
    build_live_runner,
    build_offline_runner,
    run_fixture,
)
from pilo_incident_investigator.evaluation.schema import EvalFixture

MANIFEST_PATH = Path(__file__).parents[3] / "fixtures" / "eval" / "manifest.yaml"


class FixedClock:
    def __init__(self, measurements: EvaluationMeasurements) -> None:
        self._measurements = measurements
        self.calls = 0

    def measurements(self) -> EvaluationMeasurements:
        self.calls += 1
        return self._measurements


class ProtocolLikeMeasurements:
    latency_ms = float("nan")
    input_tokens = True
    output_tokens = 1.5
    estimated_cost_usd = Decimal("0")


class MeasurementSubclass(EvaluationMeasurements):
    pass


class ScriptedPlanner:
    def __init__(
        self,
        proposals: tuple[AgentProposal, ...],
        summary: Investigation,
    ) -> None:
        self._proposals = proposals
        self._summary = summary
        self.propose_calls: list[tuple[tuple[ToolResult, ...], int]] = []
        self.summarize_calls: list[tuple[Snapshot, tuple[ToolResult, ...]]] = []

    def propose(
        self,
        snapshot: Snapshot,
        prior_results: tuple[ToolResult, ...],
        remaining_budget: int,
    ) -> AgentProposal:
        del snapshot
        self.propose_calls.append((prior_results, remaining_budget))
        return self._proposals[len(self.propose_calls) - 1]

    def summarize(
        self,
        snapshot: Snapshot,
        tool_results: tuple[ToolResult, ...] = (),
    ) -> Investigation:
        self.summarize_calls.append((snapshot, tool_results))
        return replace(self._summary, tool_calls=tool_results)


@pytest.fixture(scope="module")
def fixtures() -> tuple[EvalFixture, ...]:
    return load_manifest(MANIFEST_PATH)


@pytest.fixture(scope="module")
def composite(fixtures: tuple[EvalFixture, ...]) -> EvalFixture:
    return next(
        fixture for fixture in fixtures if fixture.fixture_id == "composite-deploy-and-backlog"
    )


def _proposal(
    fixture: EvalFixture,
    requests: tuple[ToolRequest, ...] = (),
) -> AgentProposal:
    if not fixture.snapshot.evidence:
        return AgentProposal(
            tool_requests=requests,
            facts=(),
            directions=(),
            missing=("recorded_missing_context",),
            classification="unclassified",
        )
    citation = fixture.snapshot.evidence[0].evidence_id
    return AgentProposal(
        tool_requests=requests,
        facts=(SupportedStatement("recorded bounded fact", (citation,)),),
        directions=(SupportedStatement("inspect_recorded_evidence", (citation,)),),
        missing=("recorded_missing_context",),
        classification="unclassified",
    )


def _summary(fixture: EvalFixture) -> Investigation:
    if not fixture.snapshot.evidence:
        return Investigation(
            facts=(),
            directions=(),
            missing=("recorded_missing_context",),
            classification="unclassified",
            tool_calls=(),
        )
    citation = fixture.snapshot.evidence[0].evidence_id
    return Investigation(
        facts=(SupportedStatement("recorded bounded fact", (citation,)),),
        directions=(SupportedStatement("inspect_recorded_evidence", (citation,)),),
        missing=("recorded_missing_context",),
        classification="unclassified",
        tool_calls=(),
    )


def _measurements() -> EvaluationMeasurements:
    return EvaluationMeasurements(
        latency_ms=17,
        input_tokens=101,
        output_tokens=23,
        estimated_cost_usd=Decimal("0.00042"),
    )


def _recording(fixture: EvalFixture, mode: EvaluationMode) -> RecordedEvaluation:
    requests = tuple(result.request for result in fixture.tool_results.values())
    proposals: tuple[AgentProposal, ...] = ()
    if mode is EvaluationMode.HYBRID_AGENT:
        proposals = (_proposal(fixture, requests),)
        if requests:
            proposals += (_proposal(fixture),)
    return RecordedEvaluation(
        mode=mode,
        proposals=proposals,
        final_investigation=_summary(fixture),
        measurements=_measurements(),
    )


def _recordings(
    fixtures: tuple[EvalFixture, ...],
) -> dict[tuple[str, EvaluationMode], RecordedEvaluation]:
    return {
        (fixture.fixture_id, mode): _recording(fixture, mode)
        for fixture in fixtures
        for mode in EvaluationMode
    }


def test_evaluation_modes_match_the_existing_eval_mode_literals() -> None:
    assert tuple(mode.value for mode in EvaluationMode) == (
        "snapshot_only",
        "hybrid_agent",
    )


def test_recorded_evaluation_is_immutable(composite: EvalFixture) -> None:
    recording = _recording(composite, EvaluationMode.SNAPSHOT_ONLY)

    with pytest.raises(FrozenInstanceError):
        recording.mode = EvaluationMode.HYBRID_AGENT  # type: ignore[misc]


def test_recorded_evaluation_rejects_mutable_proposal_sequence(
    composite: EvalFixture,
) -> None:
    mutable = [_proposal(composite)]

    with pytest.raises(TypeError, match="tuple"):
        RecordedEvaluation(
            mode=EvaluationMode.HYBRID_AGENT,
            proposals=mutable,  # type: ignore[arg-type]
            final_investigation=_summary(composite),
            measurements=_measurements(),
        )


@pytest.mark.parametrize(
    "values",
    [
        (-1, 0, 0, Decimal("0")),
        (0, -1, 0, Decimal("0")),
        (0, 0, -1, Decimal("0")),
        (True, 0, 0, Decimal("0")),
        (0, False, 0, Decimal("0")),
        (0, 0, True, Decimal("0")),
        (1.0, 0, 0, Decimal("0")),
        (0, 1.0, 0, Decimal("0")),
        (0, 0, 1.0, Decimal("0")),
        (0, 0, 0, -1),
        (0, 0, 0, 0.0),
        (0, 0, 0, True),
        (0, 0, 0, Decimal("-0.01")),
        (0, 0, 0, Decimal("NaN")),
        (0, 0, 0, Decimal("Infinity")),
    ],
)
def test_measurements_require_exact_nonnegative_types(
    values: tuple[object, object, object, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        EvaluationMeasurements(*values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "measurements",
    [
        cast(EvaluationMeasurements, ProtocolLikeMeasurements()),
        MeasurementSubclass(0, 0, 0, Decimal("0")),
    ],
    ids=["duck-object", "subclass"],
)
def test_run_fixture_rejects_non_exact_measurement_objects(
    composite: EvalFixture,
    measurements: EvaluationMeasurements,
) -> None:
    planner = ScriptedPlanner((), _summary(composite))

    with pytest.raises(TypeError, match="exact EvaluationMeasurements"):
        run_fixture(
            composite,
            EvaluationMode.SNAPSHOT_ONLY,
            planner,
            FixedClock(measurements),
        )


def test_offline_runner_uses_only_recorded_snapshot_output(
    fixtures: tuple[EvalFixture, ...], composite: EvalFixture
) -> None:
    runner = build_offline_runner(_recordings(fixtures))

    runs = runner.run_all(fixtures)

    snapshot = next(run for run in runs if run.mode == "snapshot_only")
    assert snapshot.investigation == _summary(composite)
    assert snapshot.tool_calls == ()
    assert snapshot.latency_ms == 17
    assert snapshot.estimated_cost_usd == Decimal("0.00042")


def test_offline_runner_replays_hybrid_proposals_through_production_agent(
    fixtures: tuple[EvalFixture, ...], composite: EvalFixture
) -> None:
    runner = build_offline_runner(_recordings(fixtures))

    runs = runner.run_all(fixtures)

    hybrid = next(
        run for run in runs if run.fixture_id == composite.fixture_id and run.mode == "hybrid_agent"
    )
    requests = tuple(result.request for result in composite.tool_results.values())
    assert hybrid.tool_calls == requests
    assert hybrid.investigation.tool_calls == tuple(composite.tool_results.values())
    assert hybrid.investigation.facts == _summary(composite).facts


def test_offline_builder_has_no_arbitrary_planner_injection(
    composite: EvalFixture,
) -> None:
    unsafe_builder = cast(Callable[..., object], build_offline_runner)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        unsafe_builder(
            {(composite.fixture_id, mode): _recording(composite, mode) for mode in EvaluationMode},
            planner_factory=lambda fixture, mode: ScriptedPlanner((), _summary(fixture)),
        )


def test_live_builder_requires_explicit_external_opt_in(composite: EvalFixture) -> None:
    factory_calls: list[str] = []

    def planner_factory(fixture: EvalFixture, mode: EvaluationMode) -> ScriptedPlanner:
        factory_calls.append(f"planner:{fixture.fixture_id}:{mode.value}")
        return ScriptedPlanner((), _summary(fixture))

    def clock_factory(fixture: EvalFixture, mode: EvaluationMode) -> FixedClock:
        factory_calls.append(f"clock:{fixture.fixture_id}:{mode.value}")
        return FixedClock(_measurements())

    with pytest.raises(LiveEvaluationDisabled, match="explicit external opt-in"):
        build_live_runner(
            planner_factory=planner_factory,
            clock_factory=clock_factory,
            allow_external=False,
        )
    assert factory_calls == []


def test_live_builder_does_not_create_or_call_clients(composite: EvalFixture) -> None:
    factory_calls: list[str] = []

    def planner_factory(fixture: EvalFixture, mode: EvaluationMode) -> ScriptedPlanner:
        factory_calls.append(f"planner:{fixture.fixture_id}:{mode.value}")
        return ScriptedPlanner((), _summary(fixture))

    def clock_factory(fixture: EvalFixture, mode: EvaluationMode) -> FixedClock:
        factory_calls.append(f"clock:{fixture.fixture_id}:{mode.value}")
        return FixedClock(_measurements())

    build_live_runner(
        planner_factory=planner_factory,
        clock_factory=clock_factory,
        allow_external=True,
    )

    assert factory_calls == []


def test_recorded_tool_lookup_ignores_reason_but_preserves_actual_request(
    composite: EvalFixture,
) -> None:
    recorded = next(iter(composite.tool_results.values())).request
    changed = replace(recorded, reason=f"{recorded.reason} model-specific explanation")
    planner = ScriptedPlanner(
        (_proposal(composite, (changed,)), _proposal(composite)),
        _summary(composite),
    )

    run = run_fixture(
        composite,
        EvaluationMode.HYBRID_AGENT,
        planner,
        FixedClock(_measurements()),
    )

    assert run.tool_calls == (changed,)
    assert run.investigation.tool_calls[0].request == changed
    assert (
        run.investigation.tool_calls[0].evidence
        == next(iter(composite.tool_results.values())).evidence
    )


def test_recorded_tool_lookup_rejects_different_request_key(composite: EvalFixture) -> None:
    recorded = next(iter(composite.tool_results.values())).request
    changed = replace(recorded, parameters={"different": True})
    planner = ScriptedPlanner((_proposal(composite, (changed,)),), _summary(composite))

    run = run_fixture(
        composite,
        EvaluationMode.HYBRID_AGENT,
        planner,
        FixedClock(_measurements()),
    )

    assert run.tool_calls == ()
    assert run.investigation.classification == "unclassified"


def test_hybrid_keeps_production_batch_budget_fail_closed(
    composite: EvalFixture,
) -> None:
    recorded = next(iter(composite.tool_results.values())).request
    planner = ScriptedPlanner(
        (_proposal(composite, (recorded, recorded, recorded, recorded)),),
        _summary(composite),
    )

    run = run_fixture(
        composite,
        EvaluationMode.HYBRID_AGENT,
        planner,
        FixedClock(_measurements()),
    )

    assert run.tool_calls == ()
    assert run.investigation.classification == "unclassified"


def test_hybrid_keeps_production_deduplication_fail_closed(
    composite: EvalFixture,
) -> None:
    recorded = next(iter(composite.tool_results.values())).request
    planner = ScriptedPlanner(
        (_proposal(composite, (recorded, recorded)),),
        _summary(composite),
    )

    run = run_fixture(
        composite,
        EvaluationMode.HYBRID_AGENT,
        planner,
        FixedClock(_measurements()),
    )

    assert run.tool_calls == ()
    assert run.investigation.classification == "unclassified"
