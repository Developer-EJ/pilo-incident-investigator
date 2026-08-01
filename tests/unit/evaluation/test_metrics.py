from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from pilo_incident_investigator.agent.loop import MAX_TOTAL_TOOLS
from pilo_incident_investigator.domain import (
    CollectorFailure,
    Investigation,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.metrics import RunMetrics, score_run
from pilo_incident_investigator.evaluation.schema import EvalFixture, EvalRun, ExpectedOutcome

MANIFEST_PATH = Path(__file__).parents[3] / "fixtures" / "eval" / "manifest.yaml"


@pytest.fixture(scope="module")
def composite() -> EvalFixture:
    return next(
        fixture
        for fixture in load_manifest(MANIFEST_PATH)
        if fixture.fixture_id == "composite-deploy-and-backlog"
    )


def _fixture(
    fixture: EvalFixture,
    *,
    required: frozenset[str] = frozenset(),
    directions: frozenset[str] = frozenset(),
    useful_tools: frozenset[str] = frozenset(),
    classification: str = "unclassified",
) -> EvalFixture:
    return replace(
        fixture,
        expected=ExpectedOutcome(
            required_evidence_ids=required,
            acceptable_direction_labels=directions,
            useful_tools=useful_tools,
            classification=classification,
            facts=(),
            missing_information=(),
        ),
    )


def _run(
    fixture: EvalFixture,
    *,
    facts: tuple[SupportedStatement, ...] = (),
    directions: tuple[SupportedStatement, ...] = (),
    classification: str = "unclassified",
    classification_evidence_ids: tuple[str, ...] = (),
    investigation_tool_calls: tuple[ToolResult, ...] = (),
    tool_calls: tuple[ToolRequest, ...] | None = None,
) -> EvalRun:
    investigation = Investigation(
        facts=facts,
        directions=directions,
        missing=(),
        classification=classification,
        tool_calls=investigation_tool_calls,
        classification_evidence_ids=classification_evidence_ids,
    )
    return EvalRun(
        fixture_id=fixture.fixture_id,
        mode="hybrid_agent",
        investigation=investigation,
        tool_calls=(
            tuple(result.request for result in investigation_tool_calls)
            if tool_calls is None
            else tool_calls
        ),
        latency_ms=17,
        input_tokens=101,
        output_tokens=23,
        estimated_cost_usd=Decimal("0.0042"),
    )


def _request(tool: str) -> ToolRequest:
    return ToolRequest(tool=tool, resource_key="synthetic", parameters={}, reason="evaluate")


def _result(tool: str) -> ToolResult:
    return ToolResult(request=_request(tool), evidence=(), failure=None)


def test_score_run_recalls_required_evidence_from_snapshot_and_tool_results(
    composite: EvalFixture,
) -> None:
    tool_evidence_id = "tool-local-sqs-status-a972adbf6bf1fa8d-1"
    fixture = _fixture(
        composite,
        required=frozenset({"E-001", tool_evidence_id, "E-NOT-CITED"}),
    )
    run = _run(
        fixture,
        facts=(SupportedStatement("snapshot fact", ("E-001",)),),
        directions=(SupportedStatement("tool direction", (tool_evidence_id,)),),
        investigation_tool_calls=(fixture.tool_results["queue-status"],),
    )

    metrics = score_run(fixture, run)

    assert metrics.required_evidence_recall == pytest.approx(2 / 3)
    assert metrics.unsupported_claims == 0


def test_score_run_empty_required_set_has_full_recall(composite: EvalFixture) -> None:
    fixture = _fixture(composite)

    assert score_run(fixture, _run(fixture)).required_evidence_recall == 1.0


def test_unknown_sparse_empty_oracle_never_marks_a_direction_correct() -> None:
    fixture = next(
        fixture
        for fixture in load_manifest(MANIFEST_PATH)
        if fixture.fixture_id == "unknown-sparse"
    )
    run = _run(
        fixture,
        directions=(SupportedStatement("plausible but unoracled", ("E-UNKNOWN",)),),
    )

    metrics = score_run(fixture, run)

    assert metrics.required_evidence_recall == 1.0
    assert metrics.correct_investigation_direction is False
    assert metrics.unclassified_applicable is True


@pytest.mark.parametrize(
    ("acceptable", "directions", "expected"),
    [
        (frozenset({"inspect_queue"}), ("inspect_queue",), True),
        (frozenset({"inspect_queue"}), ("inspect_logs", "inspect_queue"), False),
        (frozenset(), ("inspect_queue",), False),
        (frozenset({"inspect_queue"}), (), False),
    ],
)
def test_score_run_only_accepts_the_first_direction_against_a_nonempty_oracle(
    composite: EvalFixture,
    acceptable: frozenset[str],
    directions: tuple[str, ...],
    expected: bool,
) -> None:
    fixture = _fixture(composite, directions=acceptable)
    statements = tuple(SupportedStatement(text, ("E-001",)) for text in directions)

    metrics = score_run(fixture, _run(fixture, directions=statements))

    assert metrics.correct_investigation_direction is expected


def test_score_run_uses_micro_tool_counts_for_unnecessary_ratio(composite: EvalFixture) -> None:
    fixture = _fixture(composite, useful_tools=frozenset({"sqs_status"}))
    results = (_result("sqs_status"), _result("service_logs"))
    fixture = replace(fixture, tool_results={"useful": results[0], "unnecessary": results[1]})
    run = _run(fixture, investigation_tool_calls=results)

    metrics = score_run(fixture, run)

    assert metrics.tool_call_count == 2
    assert metrics.unnecessary_tool_call_count == 1
    assert metrics.unnecessary_tool_ratio == 0.5
    assert score_run(fixture, _run(fixture)).unnecessary_tool_ratio == 0.0


def test_score_run_counts_each_unsupported_statement_once(composite: EvalFixture) -> None:
    fixture = _fixture(composite)
    run = _run(
        fixture,
        facts=(
            SupportedStatement("two unknown citations", ("E-UNKNOWN-1", "E-UNKNOWN-2")),
            SupportedStatement("supported", ("E-001",)),
        ),
        directions=(SupportedStatement("mixed citations", ("E-001", "E-UNKNOWN-3")),),
    )

    metrics = score_run(fixture, run)

    assert metrics.unsupported_statement_claims == 2
    assert metrics.unsupported_classification_claims == 0
    assert metrics.unsupported_claims == 2


def test_score_run_rejects_duplicate_and_empty_statement_citations(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    empty_citation = SupportedStatement("empty citation", ("E-001",))
    object.__setattr__(empty_citation, "evidence_ids", ())
    run = _run(
        fixture,
        facts=(
            SupportedStatement("duplicate citation", ("E-001", "E-001")),
            empty_citation,
        ),
    )

    metrics = score_run(fixture, run)

    assert metrics.unsupported_statement_claims == 2
    assert metrics.unsupported_claims == 2


@pytest.mark.parametrize(
    ("classification", "citations", "unsupported"),
    [
        ("deployment_regression", (), 1),
        ("deployment_regression", ("E-UNKNOWN",), 1),
        ("deployment_regression", ("E-001",), 0),
        ("deployment_regression", ("E-001", "E-001"), 1),
        ("unclassified", (), 0),
        ("unclassified", ("E-UNKNOWN",), 1),
    ],
)
def test_score_run_tracks_classification_citation_safety_separately(
    composite: EvalFixture,
    classification: str,
    citations: tuple[str, ...],
    unsupported: int,
) -> None:
    fixture = _fixture(composite)

    metrics = score_run(
        fixture,
        _run(
            fixture,
            classification=classification,
            classification_evidence_ids=citations,
        ),
    )

    assert metrics.unsupported_statement_claims == 0
    assert metrics.unsupported_classification_claims == unsupported
    assert metrics.unsupported_claims == unsupported


@pytest.mark.parametrize(
    ("expected_classification", "actual_classification", "applicable", "correct"),
    [
        ("unclassified", "unclassified", True, True),
        ("unclassified", "ecs_oom", True, False),
        ("ecs_oom", "ecs_oom", False, False),
    ],
)
def test_score_run_only_guards_expected_unclassified_fixtures(
    composite: EvalFixture,
    expected_classification: str,
    actual_classification: str,
    applicable: bool,
    correct: bool,
) -> None:
    fixture = _fixture(composite, classification=expected_classification)

    metrics = score_run(
        fixture,
        _run(
            fixture,
            classification=actual_classification,
            classification_evidence_ids=("E-001",),
        ),
    )

    assert metrics.unclassified_applicable is applicable
    assert metrics.unclassified_correct is correct


def test_score_run_copies_strict_runtime_measurements_without_pricing_logic(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)

    metrics = score_run(fixture, _run(fixture))

    assert metrics.latency_ms == 17
    assert metrics.input_tokens == 101
    assert metrics.output_tokens == 23
    assert metrics.estimated_cost_usd == Decimal("0.0042")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("latency_ms", True),
        ("input_tokens", 1.5),
        ("output_tokens", float("nan")),
        ("estimated_cost_usd", 0.01),
    ],
)
def test_score_run_rejects_non_strict_runtime_measurements(
    composite: EvalFixture, field: str, value: object
) -> None:
    fixture = _fixture(composite)
    run = _run(fixture)
    object.__setattr__(run, field, value)

    with pytest.raises((TypeError, ValueError)):
        score_run(fixture, run)


def test_score_run_rejects_a_mismatched_fixture() -> None:
    fixtures = load_manifest(MANIFEST_PATH)

    with pytest.raises(ValueError, match="fixture ID"):
        score_run(fixtures[0], _run(fixtures[-1]))


def test_score_run_rejects_forged_tool_evidence_without_matching_run_calls(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    run = _run(
        fixture,
        investigation_tool_calls=(fixture.tool_results["queue-status"],),
        tool_calls=(),
    )

    with pytest.raises(ValueError, match="Tool calls"):
        score_run(fixture, run)


def test_score_run_rejects_a_tool_request_with_a_mismatched_reason(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    result = fixture.tool_results["queue-status"]
    mismatched = replace(result.request, reason="different reason")
    run = _run(
        fixture,
        investigation_tool_calls=(result,),
        tool_calls=(mismatched,),
    )

    with pytest.raises(ValueError, match="Tool calls"):
        score_run(fixture, run)


def test_score_run_accepts_a_recorded_result_with_an_actual_planner_reason(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    recorded = fixture.tool_results["queue-status"]
    actual = replace(recorded, request=replace(recorded.request, reason="actual planner reason"))

    metrics = score_run(fixture, _run(fixture, investigation_tool_calls=(actual,)))

    assert metrics.tool_call_count == 1


def test_score_run_rejects_tool_requests_in_a_different_order(composite: EvalFixture) -> None:
    fixture = _fixture(composite)
    results = (_result("sqs_status"), _result("service_logs"))
    run = _run(
        fixture,
        investigation_tool_calls=results,
        tool_calls=(results[1].request, results[0].request),
    )

    with pytest.raises(ValueError, match="Tool calls"):
        score_run(fixture, run)


def test_score_run_rejects_duplicate_snapshot_and_tool_evidence_ids(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    result = ToolResult(
        request=_request("sqs_status"),
        evidence=(fixture.snapshot.evidence[0],),
        failure=None,
    )
    fixture = replace(fixture, tool_results={"duplicate": result})

    with pytest.raises(ValueError, match="duplicate Evidence ID"):
        score_run(fixture, _run(fixture, investigation_tool_calls=(result,)))


@pytest.mark.parametrize("mutation", ["summary", "data", "observed_at", "evidence", "failure"])
def test_score_run_rejects_fabricated_recorded_tool_result_payloads(
    composite: EvalFixture, mutation: str
) -> None:
    fixture = _fixture(composite)
    recorded = fixture.tool_results["queue-status"]
    evidence = recorded.evidence[0]
    if mutation == "summary":
        actual = replace(recorded, evidence=(replace(evidence, summary="fabricated"),))
    elif mutation == "data":
        actual = replace(recorded, evidence=(replace(evidence, data={"fabricated": True}),))
    elif mutation == "observed_at":
        actual = replace(
            recorded,
            evidence=(replace(evidence, observed_at=evidence.observed_at + timedelta(seconds=1)),),
        )
    elif mutation == "evidence":
        actual = replace(recorded, evidence=())
    else:
        assert mutation == "failure"
        actual = replace(
            recorded,
            failure=CollectorFailure("sqs_status", "fabricated", "fabricated failure"),
        )

    with pytest.raises(ValueError, match="recorded Tool result"):
        score_run(fixture, _run(fixture, investigation_tool_calls=(actual,)))


def test_score_run_rejects_a_result_absent_from_the_recorded_fixture(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    absent = _result("service_logs")

    with pytest.raises(ValueError, match="recorded Tool result"):
        score_run(fixture, _run(fixture, investigation_tool_calls=(absent,)))


def test_score_run_rejects_duplicate_recorded_request_keys(composite: EvalFixture) -> None:
    recorded = composite.tool_results["queue-status"]
    duplicate = replace(recorded, request=replace(recorded.request, reason="duplicate reason"))
    fixture = replace(composite, tool_results={"first": recorded, "second": duplicate})

    with pytest.raises(ValueError, match="duplicate recorded Tool request"):
        score_run(fixture, _run(fixture))


def test_score_run_rejects_duplicate_executed_recorded_requests(
    composite: EvalFixture,
) -> None:
    fixture = _fixture(composite)
    recorded = fixture.tool_results["queue-status"]

    with pytest.raises(ValueError, match="duplicate executed Tool request"):
        score_run(
            fixture,
            _run(fixture, investigation_tool_calls=(recorded, recorded)),
        )


def test_score_run_rejects_duplicate_evidence_free_failure_requests(
    composite: EvalFixture,
) -> None:
    failure = ToolResult(
        request=_request("sqs_status"),
        evidence=(),
        failure=CollectorFailure("sqs_status", "synthetic", "synthetic failure"),
    )
    fixture = replace(_fixture(composite), tool_results={"failure": failure})

    with pytest.raises(ValueError, match="duplicate executed Tool request"):
        score_run(
            fixture,
            _run(fixture, investigation_tool_calls=(failure, failure)),
        )


def test_score_run_rejects_more_than_the_agent_tool_budget(composite: EvalFixture) -> None:
    results = tuple(
        ToolResult(
            request=ToolRequest(
                tool="service_logs",
                resource_key=f"synthetic-{index}",
                parameters={},
                reason="evaluate",
            ),
            evidence=(),
            failure=CollectorFailure("service_logs", "synthetic", "synthetic failure"),
        )
        for index in range(MAX_TOTAL_TOOLS + 1)
    )
    fixture = replace(
        _fixture(composite),
        tool_results={f"result-{index}": result for index, result in enumerate(results)},
    )

    with pytest.raises(ValueError, match="Tool call budget"):
        score_run(fixture, _run(fixture, investigation_tool_calls=results))


def _valid_metrics() -> RunMetrics:
    return RunMetrics(
        fixture_id="fixture-a",
        mode="snapshot_only",
        required_evidence_recall=1.0,
        correct_investigation_direction=True,
        unnecessary_tool_ratio=0.0,
        unsupported_claims=0,
        unsupported_statement_claims=0,
        unsupported_classification_claims=0,
        unclassified_applicable=True,
        unclassified_correct=True,
        tool_call_count=0,
        unnecessary_tool_call_count=0,
        latency_ms=1,
        input_tokens=2,
        output_tokens=3,
        estimated_cost_usd=Decimal("0.01"),
    )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("mode", "unknown", TypeError),
        ("required_evidence_recall", True, TypeError),
        ("required_evidence_recall", float("nan"), ValueError),
        ("unnecessary_tool_ratio", float("inf"), ValueError),
        ("unsupported_claims", True, TypeError),
        ("latency_ms", 1.0, TypeError),
        ("estimated_cost_usd", 0.01, TypeError),
        ("estimated_cost_usd", Decimal("NaN"), ValueError),
    ],
)
def test_run_metrics_rejects_non_strict_or_nonfinite_values(
    field: str, value: object, error: type[Exception]
) -> None:
    metrics = _valid_metrics()
    object.__setattr__(metrics, field, value)
    with pytest.raises(error):
        metrics.__post_init__()


def test_run_metrics_rejects_inconsistent_derived_counts() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        replace(_valid_metrics(), unsupported_claims=1)
    with pytest.raises(ValueError, match="Tool"):
        replace(_valid_metrics(), unnecessary_tool_call_count=1)
