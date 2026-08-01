from pathlib import Path

import pytest

from pilo_incident_investigator.evaluation.handoff import (
    CONDITIONS,
    HandoffActionProposal,
    HandoffOutput,
    HandoffRecording,
    build_handoff_prompt,
    build_offline_handoff_harness,
    fixture_digest,
    prompt_digest,
    tool_registry_identifier,
)
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.schema import EvalFixture

MANIFEST_PATH = Path(__file__).parents[2] / "fixtures" / "eval" / "manifest.yaml"
MODEL_ID = "synthetic-model-v1"
PROMPT_BUDGET = 512


@pytest.fixture(scope="module")
def fixtures() -> tuple[EvalFixture, ...]:
    return load_manifest(MANIFEST_PATH)


def _recordings(fixtures: tuple[EvalFixture, ...]) -> dict[tuple[str, str], HandoffRecording]:
    recordings: dict[tuple[str, str], HandoffRecording] = {}
    for fixture in fixtures:
        for condition in CONDITIONS:
            prompt = build_handoff_prompt(fixture, condition)
            recordings[(fixture.fixture_id, condition)] = HandoffRecording(
                fixture_id=fixture.fixture_id,
                condition=condition,
                model_id=MODEL_ID,
                prompt_budget=PROMPT_BUDGET,
                prompt_digest=prompt_digest(prompt),
                fixture_digest=fixture_digest(fixture),
                tool_registry_id=tool_registry_identifier(fixture),
                output=HandoffOutput(
                    first_direction_label=None,
                    clarification_requests=(),
                    claims=(),
                    action_proposals=(
                        (HandoffActionProposal("restart the ECS service now"),)
                        if fixture.fixture_id == "ecs-oom-complete" and condition == "raw_alarm"
                        else ()
                    ),
                    tool_requests=(),
                ),
            )
    return recordings


def test_all_fixtures_run_two_isolated_offline_handoff_conditions(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=_recordings(fixtures),
    )

    runs = harness.run_all(fixtures)

    assert len(runs) == 42
    assert {(run.fixture_id, run.condition) for run in runs} == {
        (fixture.fixture_id, condition) for fixture in fixtures for condition in CONDITIONS
    }
    pairs = {fixture.fixture_id: harness.run_pair(fixture) for fixture in fixtures}
    assert all(raw.model_id == brief.model_id == MODEL_ID for raw, brief in pairs.values())
    assert all(
        raw.prompt_budget == brief.prompt_budget == PROMPT_BUDGET for raw, brief in pairs.values()
    )
    sparse = pairs["unknown-sparse"]
    assert sparse[0].first_direction_label is sparse[1].first_direction_label is None
    assert sparse[0].additional_tool_calls == sparse[1].additional_tool_calls == 0
    assert any(run.forbidden_action_proposals == 1 for run in runs)


def test_offline_handoff_requires_an_exact_twenty_one_by_two_recording_matrix(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    recordings = _recordings(fixtures)
    recordings.pop((fixtures[0].fixture_id, "raw_alarm"))
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="recording matrix"):
        harness.run_all(fixtures)
