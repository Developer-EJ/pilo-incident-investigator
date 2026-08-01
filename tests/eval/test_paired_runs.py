import json
import socket
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path

import pytest

from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.domain import Investigation, SupportedStatement
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.runner import (
    EvaluationMeasurements,
    EvaluationMode,
    RecordedEvaluation,
    build_offline_runner,
)
from pilo_incident_investigator.evaluation.schema import EvalFixture, EvalRun

MANIFEST_PATH = Path(__file__).parents[2] / "fixtures" / "eval" / "manifest.yaml"
UNKNOWN_SPARSE_MISSING = (
    "target_mapping",
    "related_logs",
    "target_health",
    "pilo_service_states",
)


def _generic_investigation(fixture: EvalFixture) -> Investigation:
    if not fixture.snapshot.evidence:
        return Investigation(
            facts=(),
            directions=(),
            missing=(
                UNKNOWN_SPARSE_MISSING
                if fixture.fixture_id == "unknown-sparse"
                else ("recorded_missing_context",)
            ),
            classification="unclassified",
            tool_calls=(),
        )
    citation = fixture.snapshot.evidence[0].evidence_id
    return Investigation(
        facts=(SupportedStatement("recorded bounded observation", (citation,)),),
        directions=(SupportedStatement("inspect_recorded_bounded_evidence", (citation,)),),
        missing=("recorded_missing_context",),
        classification="unclassified",
        tool_calls=(),
    )


def _generic_proposal(
    fixture: EvalFixture,
    *,
    include_tools: bool,
) -> AgentProposal:
    investigation = _generic_investigation(fixture)
    requests = (
        tuple(result.request for result in fixture.tool_results.values()) if include_tools else ()
    )
    return AgentProposal(
        tool_requests=requests,
        facts=investigation.facts,
        directions=investigation.directions,
        missing=investigation.missing,
        classification=investigation.classification,
        classification_evidence_ids=investigation.classification_evidence_ids,
    )


def _recording(fixture: EvalFixture, mode: EvaluationMode) -> RecordedEvaluation:
    proposals: tuple[AgentProposal, ...] = ()
    if mode is EvaluationMode.HYBRID_AGENT:
        proposals = (_generic_proposal(fixture, include_tools=True),)
        if fixture.tool_results:
            proposals += (_generic_proposal(fixture, include_tools=False),)
    measurements = (
        EvaluationMeasurements(10, 100, 20, Decimal("0.001"))
        if mode is EvaluationMode.SNAPSHOT_ONLY
        else EvaluationMeasurements(20, 150, 30, Decimal("0.002"))
    )
    return RecordedEvaluation(
        mode=mode,
        proposals=proposals,
        final_investigation=_generic_investigation(fixture),
        measurements=measurements,
    )


def _recordings(
    fixtures: tuple[EvalFixture, ...],
) -> dict[tuple[str, EvaluationMode], RecordedEvaluation]:
    return {
        (fixture.fixture_id, mode): _recording(fixture, mode)
        for fixture in fixtures
        for mode in EvaluationMode
    }


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return str(value.value)
    raise TypeError(f"unsupported value: {type(value).__name__}")


def _encoded(runs: tuple[EvalRun, ...]) -> bytes:
    return json.dumps(
        [asdict(run) for run in runs],
        default=_json_default,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@pytest.fixture(scope="module")
def fixtures() -> tuple[EvalFixture, ...]:
    return load_manifest(MANIFEST_PATH)


def test_each_fixture_runs_both_recorded_modes_without_external_calls(
    fixtures: tuple[EvalFixture, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("offline evaluation attempted a network call")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    runner = build_offline_runner(_recordings(fixtures))

    runs = runner.run_all(fixtures)

    assert len(runs) == 42
    assert len({(run.fixture_id, run.mode) for run in runs}) == 42
    assert {(run.fixture_id, run.mode) for run in runs} == {
        (fixture.fixture_id, mode.value) for fixture in fixtures for mode in EvaluationMode
    }
    fixtures_by_id = {fixture.fixture_id: fixture for fixture in fixtures}
    for run in runs:
        recorded = tuple(
            result.request for result in fixtures_by_id[run.fixture_id].tool_results.values()
        )
        assert run.tool_calls == (recorded if run.mode == "hybrid_agent" else ())


def test_unknown_sparse_recording_is_conservative_without_reading_oracle(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    runner = build_offline_runner(_recordings(fixtures))

    runs = runner.run_all(fixtures)

    sparse = [run for run in runs if run.fixture_id == "unknown-sparse"]
    assert len(sparse) == 2
    assert all(run.investigation.directions == () for run in sparse)
    assert all(run.investigation.missing == UNKNOWN_SPARSE_MISSING for run in sparse)
    assert all(run.investigation.classification == "unclassified" for run in sparse)


@pytest.mark.parametrize("kind", ["missing", "extra", "mode-mismatch"])
def test_offline_runner_rejects_incomplete_or_mismatched_recordings_before_running(
    fixtures: tuple[EvalFixture, ...],
    kind: str,
) -> None:
    recordings = _recordings(fixtures)
    first_key = next(iter(recordings))
    if kind == "missing":
        recordings.pop(first_key)
    elif kind == "extra":
        recordings[("not-a-loaded-fixture", EvaluationMode.SNAPSHOT_ONLY)] = recordings[first_key]
    else:
        fixture_id, mode = first_key
        other_mode = (
            EvaluationMode.HYBRID_AGENT
            if mode is EvaluationMode.SNAPSHOT_ONLY
            else EvaluationMode.SNAPSHOT_ONLY
        )
        recordings[first_key] = recordings[(fixture_id, other_mode)]
    runner = build_offline_runner(recordings)

    with pytest.raises(ValueError, match="recording"):
        runner.run_all(fixtures)


def test_offline_runner_rejects_duplicate_fixture_ids(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    runner = build_offline_runner(_recordings(fixtures))

    with pytest.raises(ValueError, match="duplicate fixture"):
        runner.run_all((*fixtures, fixtures[0]))


def test_offline_runner_requires_the_complete_twenty_one_fixture_set(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    incomplete = fixtures[:-1]
    runner = build_offline_runner(_recordings(incomplete))

    with pytest.raises(ValueError, match="exactly 21 fixtures"):
        runner.run_all(incomplete)


def test_repeated_offline_runs_are_byte_identical(fixtures: tuple[EvalFixture, ...]) -> None:
    runner = build_offline_runner(_recordings(fixtures))

    first = _encoded(runner.run_all(fixtures))
    second = _encoded(runner.run_all(fixtures))

    assert first == second


def test_builder_snapshots_nested_recording_data_at_ingestion() -> None:
    fixtures = load_manifest(MANIFEST_PATH)
    recordings = deepcopy(_recordings(fixtures))
    runner = build_offline_runner(recordings)
    pristine = _encoded(runner.run_all(fixtures))
    composite = next(
        fixture for fixture in fixtures if fixture.fixture_id == "composite-deploy-and-backlog"
    )
    recording = recordings[(composite.fixture_id, EvaluationMode.HYBRID_AGENT)]

    recording.proposals[0].tool_requests[0].parameters["mutated_after_build"] = True

    assert _encoded(runner.run_all(fixtures)) == pristine


def test_mutating_one_run_does_not_change_fixture_or_future_run() -> None:
    fixtures = load_manifest(MANIFEST_PATH)
    runner = build_offline_runner(deepcopy(_recordings(fixtures)))
    pristine = _encoded(runner.run_all(fixtures))
    first = runner.run_all(fixtures)
    composite = next(
        run
        for run in first
        if run.fixture_id == "composite-deploy-and-backlog" and run.mode == "hybrid_agent"
    )

    composite.tool_calls[0].parameters["mutated_run_request"] = True
    composite.investigation.tool_calls[0].evidence[0].data["mutated_run_evidence"] = True

    assert _encoded(runner.run_all(fixtures)) == pristine
    reloaded = load_manifest(MANIFEST_PATH)
    assert _encoded(runner.run_all(reloaded)) == pristine


def test_returned_run_does_not_change_after_original_recording_mutation() -> None:
    fixtures = load_manifest(MANIFEST_PATH)
    recordings = deepcopy(_recordings(fixtures))
    runner = build_offline_runner(recordings)
    first = runner.run_all(fixtures)
    before = _encoded(first)
    composite = next(
        fixture for fixture in fixtures if fixture.fixture_id == "composite-deploy-and-backlog"
    )
    recording = recordings[(composite.fixture_id, EvaluationMode.HYBRID_AGENT)]

    recording.proposals[0].tool_requests[0].parameters["late_mutation"] = True

    assert _encoded(first) == before


@pytest.mark.parametrize(
    "kind",
    ["stale-after-no-tool", "third-round", "rejected-with-remaining"],
)
def test_offline_runner_rejects_unconsumed_recorded_proposals(
    fixtures: tuple[EvalFixture, ...],
    kind: str,
) -> None:
    recordings = _recordings(fixtures)
    composite = next(
        fixture for fixture in fixtures if fixture.fixture_id == "composite-deploy-and-backlog"
    )
    key = (composite.fixture_id, EvaluationMode.HYBRID_AGENT)
    recording = recordings[key]
    no_tool = _generic_proposal(composite, include_tools=False)
    proposals: tuple[AgentProposal, ...]
    if kind == "stale-after-no-tool":
        proposals = (no_tool, no_tool)
    elif kind == "third-round":
        proposals = (*recording.proposals, no_tool)
    else:
        first = recording.proposals[0]
        request = first.tool_requests[0]
        rejected = replace(
            first,
            tool_requests=(replace(request, parameters={"not_recorded": True}),),
        )
        proposals = (rejected, no_tool)
    recordings[key] = replace(recording, proposals=proposals)
    runner = build_offline_runner(recordings)

    with pytest.raises(ValueError, match="unconsumed recorded proposals"):
        runner.run_all(fixtures)
