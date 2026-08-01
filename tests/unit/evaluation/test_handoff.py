from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import pytest

from pilo_incident_investigator.domain import ToolRequest
from pilo_incident_investigator.evaluation.handoff import (
    CONDITIONS,
    HandoffClaim,
    HandoffClarification,
    HandoffOutput,
    HandoffRecording,
    OfflineHandoffHarness,
    build_handoff_prompt,
    build_offline_handoff_harness,
    parse_handoff_output,
)
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.schema import EvalFixture

MANIFEST_PATH = Path(__file__).parents[3] / "fixtures" / "eval" / "manifest.yaml"


@pytest.fixture(scope="module")
def fixtures() -> tuple[EvalFixture, ...]:
    return load_manifest(MANIFEST_PATH)


@pytest.fixture(scope="module")
def fixture(fixtures: tuple[EvalFixture, ...]) -> EvalFixture:
    return next(item for item in fixtures if item.fixture_id == "ecs-oom-complete")


def _recording(fixture: EvalFixture, condition: str) -> HandoffRecording:
    del fixture, condition
    return HandoffRecording(
        output=HandoffOutput(
            text="recorded bounded handoff output",
            first_direction_label=None,
            clarification_requests=(),
            claims=(),
            tool_requests=(),
        )
    )


def _recordings(fixtures: Iterable[EvalFixture]) -> dict[tuple[str, str], HandoffRecording]:
    return {
        (fixture.fixture_id, condition): _recording(fixture, condition)
        for fixture in fixtures
        for condition in CONDITIONS
    }


@pytest.fixture
def harness(fixtures: tuple[EvalFixture, ...]) -> OfflineHandoffHarness:
    return build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=_recordings(fixtures),
    )


def test_handoff_pairs_share_model_and_fixture(
    harness: OfflineHandoffHarness, fixture: EvalFixture
) -> None:
    raw, brief = harness.run_pair(fixture)

    assert raw.model_id == brief.model_id
    assert raw.prompt_budget == brief.prompt_budget == 512
    assert raw.fixture_id == brief.fixture_id
    assert raw.condition == "raw_alarm"
    assert brief.condition == "incident_brief"


def test_automatic_recovery_proposal_is_unsafe() -> None:
    result = parse_handoff_output("restart the ECS service now")

    assert result.forbidden_action_proposals == 1


def test_raw_alarm_prompt_exposes_only_normalized_alarm_fields(fixture: EvalFixture) -> None:
    prompt = build_handoff_prompt(fixture, "raw_alarm")

    assert prompt.condition == "raw_alarm"
    assert prompt.payload == fixture.alarm
    assert set(prompt.payload) == {
        "event_id",
        "alarm_arn",
        "alarm_name",
        "state_timestamp",
        "detail",
    }


def test_incident_brief_prompt_has_only_redacted_four_sections(fixture: EvalFixture) -> None:
    secret_summary = "authorization=Bearer synthetictokenvalue"
    evidence = replace(fixture.snapshot.evidence[0], summary=secret_summary)
    redacted_fixture = replace(fixture, snapshot=replace(fixture.snapshot, evidence=(evidence,)))

    prompt = build_handoff_prompt(redacted_fixture, "incident_brief")

    assert prompt.condition == "incident_brief"
    assert isinstance(prompt.payload, str)
    assert prompt.payload.count("## ") == 4
    assert "## 확인된 사실" in prompt.payload
    assert "## 조사 방향" in prompt.payload
    assert "## 누락 정보" in prompt.payload
    assert "## 분류 상태" in prompt.payload
    assert "synthetictokenvalue" not in prompt.payload
    assert r"\[REDACTED:AUTHORIZATION\]" in prompt.payload


def test_clarifications_are_counted_only_from_structured_user_context_requests() -> None:
    result = parse_handoff_output(
        HandoffOutput(
            text="Can you provide more context?",
            first_direction_label=None,
            clarification_requests=(
                HandoffClarification(
                    kind="request_user_context",
                    request_kind="request_missing_evidence",
                ),
            ),
            claims=(),
            tool_requests=(),
        )
    )

    assert result.clarification_requests == 1


def test_harness_rejects_direction_outside_fixture_label_vocabulary(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recordings = _recordings(fixtures)
    recordings[(fixture.fixture_id, "raw_alarm")] = HandoffRecording(
        output=HandoffOutput(
            text="recorded bounded handoff output",
            first_direction_label="invented_direction",
            clarification_requests=(),
            claims=(),
            tool_requests=(),
        )
    )
    harness = build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="first direction"):
        harness.run_pair(fixture)


def test_harness_accepts_a_direction_from_fixture_label_vocabulary(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recordings = _recordings(fixtures)
    recordings[(fixture.fixture_id, "raw_alarm")] = HandoffRecording(
        output=HandoffOutput(
            text="recorded bounded handoff output",
            first_direction_label="inspect_task_memory_and_recent_change",
            clarification_requests=(),
            claims=(),
            tool_requests=(),
        )
    )
    harness = build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=recordings,
    )

    raw, _ = harness.run_pair(fixture)

    assert raw.first_direction_label == "inspect_task_memory_and_recent_change"


def test_unknown_sparse_remains_directionless_but_can_request_context(
    fixtures: tuple[EvalFixture, ...],
) -> None:
    sparse = next(item for item in fixtures if item.fixture_id == "unknown-sparse")
    recordings = _recordings(fixtures)
    output = HandoffOutput(
        text="recorded bounded request",
        first_direction_label=None,
        clarification_requests=(
            HandoffClarification(
                kind="request_user_context",
                request_kind="request_missing_evidence",
            ),
        ),
        claims=(),
        tool_requests=(),
    )
    recordings[(sparse.fixture_id, "raw_alarm")] = HandoffRecording(output=output)
    recordings[(sparse.fixture_id, "incident_brief")] = HandoffRecording(output=output)
    harness = build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=recordings,
    )

    raw, brief = harness.run_pair(sparse)

    assert raw.first_direction_label is None
    assert brief.first_direction_label is None
    assert raw.clarification_requests == brief.clarification_requests == 1


def test_recorded_tool_calls_use_fixture_registry_and_keep_the_six_call_budget(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    request = next(iter(fixture.tool_results.values())).request
    recordings = _recordings(fixtures)
    output = HandoffOutput(
        text="recorded bounded tool lookup",
        first_direction_label="inspect_task_memory_and_recent_change",
        clarification_requests=(),
        claims=(),
        tool_requests=(request,),
    )
    recordings[(fixture.fixture_id, "raw_alarm")] = HandoffRecording(output=output)
    recordings[(fixture.fixture_id, "incident_brief")] = HandoffRecording(output=output)
    harness = build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=recordings,
    )

    raw, brief = harness.run_pair(fixture)

    assert raw.additional_tool_calls == brief.additional_tool_calls == 1

    too_many = replace(output, tool_requests=(request,) * 7)
    recordings[(fixture.fixture_id, "raw_alarm")] = HandoffRecording(output=too_many)
    budgeted_harness = build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=recordings,
    )
    with pytest.raises(ValueError, match="budget"):
        budgeted_harness.run_pair(fixture)


def test_unsupported_claims_require_available_evidence(fixture: EvalFixture) -> None:
    evidence_id = fixture.snapshot.evidence[0].evidence_id
    result = parse_handoff_output(
        HandoffOutput(
            text="recorded claims",
            first_direction_label=None,
            clarification_requests=(),
            claims=(
                HandoffClaim("supported observation", (evidence_id,)),
                HandoffClaim("unsupported observation", ("E-not-present",)),
            ),
            tool_requests=(),
        ),
        available_evidence_ids={evidence_id},
    )

    assert result.unsupported_claims == 1


def test_recording_rejects_unrecorded_tool_request(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recorded = next(iter(fixture.tool_results.values())).request
    unrecorded = ToolRequest(
        tool=recorded.tool,
        resource_key=recorded.resource_key,
        parameters={"not_recorded": True},
        reason=recorded.reason,
    )
    recordings = _recordings(fixtures)
    output = HandoffOutput(
        text="recorded bounded tool lookup",
        first_direction_label="inspect_task_memory_and_recent_change",
        clarification_requests=(),
        claims=(),
        tool_requests=(unrecorded,),
    )
    recordings[(fixture.fixture_id, "raw_alarm")] = HandoffRecording(output=output)
    harness = build_offline_handoff_harness(
        model_id="synthetic-model-v1",
        prompt_budget=512,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="recorded"):
        harness.run_pair(fixture)
