from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from pilo_incident_investigator.domain import CollectorFailure, ToolRequest
from pilo_incident_investigator.evaluation.handoff import (
    CONDITIONS,
    HandoffClaim,
    HandoffClarification,
    HandoffCondition,
    HandoffOutput,
    HandoffRecording,
    OfflineHandoffHarness,
    build_handoff_prompt,
    build_offline_handoff_harness,
    fixture_digest,
    parse_handoff_output,
    prompt_digest,
    tool_registry_identifier,
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


MODEL_ID = "synthetic-model-v1"
PROMPT_BUDGET = 512


def _recording(
    fixture: EvalFixture,
    condition: HandoffCondition,
    output: HandoffOutput | None = None,
) -> HandoffRecording:
    prompt = build_handoff_prompt(fixture, condition)
    return HandoffRecording(
        fixture_id=fixture.fixture_id,
        condition=condition,
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        prompt_digest=prompt_digest(prompt),
        fixture_digest=fixture_digest(fixture),
        tool_registry_id=tool_registry_identifier(fixture),
        output=output
        or HandoffOutput(
            text="recorded bounded handoff output",
            first_direction_label=None,
            clarification_requests=(),
            claims=(),
            tool_requests=(),
        ),
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
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=_recordings(fixtures),
    )


def test_handoff_pairs_share_model_and_fixture(
    harness: OfflineHandoffHarness, fixture: EvalFixture
) -> None:
    raw, brief = harness.run_pair(fixture)

    assert raw.model_id == brief.model_id
    assert raw.prompt_budget == brief.prompt_budget == PROMPT_BUDGET
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


@pytest.mark.parametrize(
    ("alarm", "message"),
    [
        ({"unexpected": "field"}, "fields"),
        ({}, "fields"),
        (
            {
                "event_id": "",
                "alarm_arn": "a",
                "alarm_name": "n",
                "state_timestamp": "2026-01-01T00:00:00Z",
                "detail": {},
            },
            "text",
        ),
        (
            {
                "event_id": "e",
                "alarm_arn": "a",
                "alarm_name": "n",
                "state_timestamp": "2026-01-01T00:00:00",
                "detail": {},
            },
            "timestamp",
        ),
        (
            {
                "event_id": "e",
                "alarm_arn": "a",
                "alarm_name": "n",
                "state_timestamp": "2026-01-01T00:00:00Z",
                "detail": {"bad": {1: "key"}},
            },
            "detail",
        ),
    ],
)
def test_raw_alarm_prompt_rejects_non_normalized_alarm_contract(
    fixture: EvalFixture, alarm: dict[str, object], message: str
) -> None:
    candidate = replace(fixture, alarm=alarm)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=message):
        build_handoff_prompt(candidate, "raw_alarm")


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
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(
        fixture,
        "raw_alarm",
        HandoffOutput(
            text="recorded bounded handoff output",
            first_direction_label="invented_direction",
            clarification_requests=(),
            claims=(),
            tool_requests=(),
        ),
    )
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="first direction"):
        harness.run_pair(fixture)


def test_harness_accepts_a_direction_from_fixture_label_vocabulary(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recordings = _recordings(fixtures)
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(
        fixture,
        "raw_alarm",
        HandoffOutput(
            text="recorded bounded handoff output",
            first_direction_label="inspect_task_memory_and_recent_change",
            clarification_requests=(),
            claims=(),
            tool_requests=(),
        ),
    )
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
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
    recordings[(sparse.fixture_id, "raw_alarm")] = _recording(sparse, "raw_alarm", output)
    recordings[(sparse.fixture_id, "incident_brief")] = _recording(sparse, "incident_brief", output)
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
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
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(fixture, "raw_alarm", output)
    recordings[(fixture.fixture_id, "incident_brief")] = _recording(
        fixture, "incident_brief", output
    )
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    raw, brief = harness.run_pair(fixture)

    assert raw.additional_tool_calls == brief.additional_tool_calls == 1

    too_many = replace(output, tool_requests=(request,) * 7)
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(fixture, "raw_alarm", too_many)
    budgeted_harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
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
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(fixture, "raw_alarm", output)
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="recorded"):
        harness.run_pair(fixture)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda recording: replace(recording, fixture_id="other-fixture"),
        lambda recording: replace(recording, condition="incident_brief"),
        lambda recording: replace(recording, model_id="other-model"),
        lambda recording: replace(recording, prompt_budget=513),
        lambda recording: replace(recording, prompt_digest="0" * 64),
        lambda recording: replace(recording, tool_registry_id="0" * 64),
    ],
)
def test_recording_provenance_must_match_the_replay_context(
    fixture: EvalFixture,
    fixtures: tuple[EvalFixture, ...],
    mutate: Callable[[HandoffRecording], HandoffRecording],
) -> None:
    recordings = _recordings(fixtures)
    recording = recordings[(fixture.fixture_id, "raw_alarm")]
    recordings[(fixture.fixture_id, "raw_alarm")] = mutate(recording)
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="provenance"):
        harness.run_pair(fixture)


def test_recording_rejects_raw_and_brief_prompt_swap(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recordings = _recordings(fixtures)
    raw_key = (fixture.fixture_id, "raw_alarm")
    brief_key = (fixture.fixture_id, "incident_brief")
    recordings[raw_key], recordings[brief_key] = recordings[brief_key], recordings[raw_key]
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="provenance"):
        harness.run_pair(fixture)


def test_recording_rejects_prompt_or_registry_mutation_after_recording(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recordings = _recordings(fixtures)
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )
    prompt_mutated = deepcopy(fixture)
    detail = prompt_mutated.alarm["detail"]
    assert isinstance(detail, dict)
    detail["added_after_recording"] = True

    with pytest.raises(ValueError, match="provenance"):
        harness.run_pair(prompt_mutated)

    registry_mutated = deepcopy(fixture)
    request = next(iter(registry_mutated.tool_results.values())).request
    request.parameters["added_after_recording"] = True
    with pytest.raises(ValueError, match="provenance"):
        harness.run_pair(registry_mutated)


def test_direct_and_factory_harnesses_snapshot_mutable_recordings(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    request = deepcopy(next(iter(fixture.tool_results.values())).request)
    output = HandoffOutput(
        text="recorded bounded tool lookup",
        first_direction_label=None,
        clarification_requests=(),
        claims=(),
        tool_requests=(request,),
    )
    recordings = _recordings(fixtures)
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(fixture, "raw_alarm", output)
    direct = OfflineHandoffHarness(MODEL_ID, PROMPT_BUDGET, recordings)
    factory = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )
    request.parameters["mutated_after_build"] = True
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(fixture, "raw_alarm")

    assert direct.run_pair(fixture)[0].additional_tool_calls == 1
    assert factory.run_pair(fixture)[0].additional_tool_calls == 1


def test_recorded_tool_replay_preserves_the_recorded_result_payload(fixture: EvalFixture) -> None:
    from pilo_incident_investigator.evaluation.handoff import _RecordedToolHandler

    expected = next(iter(fixture.tool_results.values()))
    recorded_before_mutation = deepcopy(expected)
    handler = _RecordedToolHandler(fixture.tool_results)
    actual = handler.execute(expected.request)
    expected.evidence[0].data["mutated_after_snapshot"] = True

    assert actual == recorded_before_mutation
    assert "mutated_after_snapshot" not in actual.evidence[0].data


def test_recorded_tool_handler_rejects_duplicate_deduplication_keys(fixture: EvalFixture) -> None:
    from pilo_incident_investigator.evaluation.handoff import _RecordedToolHandler

    mutated = deepcopy(fixture)
    first_key, second_key = tuple(mutated.tool_results)[:2]
    mutated.tool_results[second_key] = replace(
        mutated.tool_results[second_key], request=mutated.tool_results[first_key].request
    )

    with pytest.raises(ValueError, match="duplicate"):
        _RecordedToolHandler(mutated.tool_results)


def test_actual_tool_reason_must_cite_evidence_even_when_deduplication_matches(
    fixture: EvalFixture, fixtures: tuple[EvalFixture, ...]
) -> None:
    recorded = next(iter(fixture.tool_results.values())).request
    changed_reason = replace(recorded, reason="this lookup has no Evidence citation")
    recordings = _recordings(fixtures)
    recordings[(fixture.fixture_id, "raw_alarm")] = _recording(
        fixture,
        "raw_alarm",
        HandoffOutput(
            text="recorded tool lookup",
            first_direction_label=None,
            clarification_requests=(),
            claims=(),
            tool_requests=(changed_reason,),
        ),
    )
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=recordings,
    )

    with pytest.raises(ValueError, match="reason"):
        harness.run_pair(fixture)


def test_forbidden_actions_count_distinct_regex_matches_without_duplicate_text() -> None:
    paired_actions = parse_handoff_output("restart the ECS service now; delete the cache")
    repeated_action = parse_handoff_output(
        HandoffOutput(
            text="restart the ECS service now",
            first_direction_label=None,
            clarification_requests=(),
            claims=(HandoffClaim("restart the ECS service now", ()),),
            tool_requests=(),
        )
    )

    assert paired_actions.forbidden_action_proposals == 2
    assert repeated_action.forbidden_action_proposals == 1


@pytest.mark.parametrize(
    "mutate_fixture",
    [
        lambda fixture: replace(
            fixture,
            snapshot=replace(
                fixture.snapshot,
                evidence=(replace(fixture.snapshot.evidence[0], summary="changed observation"),),
            ),
        ),
        lambda fixture: replace(
            fixture,
            snapshot=replace(
                fixture.snapshot,
                failures=(CollectorFailure("changed", "failed", "changed failure"),),
            ),
        ),
        lambda fixture: replace(
            fixture,
            handoff=replace(
                fixture.handoff,
                acceptable_first_direction_labels=frozenset({"changed_direction"}),
            ),
        ),
        lambda fixture: replace(
            fixture,
            handoff=replace(
                fixture.handoff,
                allowed_clarification_kinds=frozenset({"changed_request"}),
            ),
        ),
        lambda fixture: replace(
            fixture,
            topology=replace(
                fixture.topology,
                services=(
                    replace(fixture.topology.services[0], log_groups=("/changed/log-group",)),
                    *fixture.topology.services[1:],
                ),
            ),
        ),
    ],
)
def test_recording_rejects_same_id_fixture_state_mutations(
    fixture: EvalFixture,
    fixtures: tuple[EvalFixture, ...],
    mutate_fixture: Callable[[EvalFixture], EvalFixture],
) -> None:
    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=_recordings(fixtures),
    )

    with pytest.raises(ValueError, match="provenance"):
        harness.run_pair(mutate_fixture(fixture))


def test_recording_rejects_tool_set_change_before_replay(
    fixture: EvalFixture,
    fixtures: tuple[EvalFixture, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pilo_incident_investigator.evaluation import handoff

    harness = build_offline_handoff_harness(
        model_id=MODEL_ID,
        prompt_budget=PROMPT_BUDGET,
        recordings=_recordings(fixtures),
    )
    monkeypatch.setattr(handoff, "TOOL_NAMES", frozenset({"service_log_search"}))

    with pytest.raises(ValueError, match="provenance"):
        harness.run_pair(fixture)
