from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.metrics import (
    EVALUATION_FIXTURE_IDS,
    UNCLASSIFIED_FIXTURE_IDS,
    ComparisonMetrics,
    ModeMetrics,
    RunMetrics,
    compare_modes,
    select_operating_mode,
)
from pilo_incident_investigator.evaluation.schema import EvalMode

FIXTURE_IDS = tuple(sorted(EVALUATION_FIXTURE_IDS))
MODES: tuple[EvalMode, ...] = ("snapshot_only", "hybrid_agent")
MANIFEST_PATH = Path(__file__).parents[2] / "fixtures" / "eval" / "manifest.yaml"


def _run_metrics(
    fixture_id: str,
    mode: EvalMode,
    *,
    recall: float = 1.0,
    correct: bool = False,
    tool_calls: int = 0,
    unnecessary_calls: int = 0,
    unsupported_statements: int = 0,
    unsupported_classifications: int = 0,
    guarded: bool = False,
    unclassified_correct: bool = False,
    latency_ms: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cost: str = "0",
) -> RunMetrics:
    unsupported = unsupported_statements + unsupported_classifications
    return RunMetrics(
        fixture_id=fixture_id,
        mode=mode,
        required_evidence_recall=recall,
        correct_investigation_direction=correct,
        unnecessary_tool_ratio=unnecessary_calls / tool_calls if tool_calls else 0.0,
        unsupported_claims=unsupported,
        unsupported_statement_claims=unsupported_statements,
        unsupported_classification_claims=unsupported_classifications,
        unclassified_applicable=guarded,
        unclassified_correct=unclassified_correct,
        tool_call_count=tool_calls,
        unnecessary_tool_call_count=unnecessary_calls,
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost_usd=Decimal(cost),
    )


def _complete_matrix(
    *,
    hide_unclassified: bool = False,
    guard_representative: bool = False,
) -> tuple[RunMetrics, ...]:
    rows: list[RunMetrics] = []
    for index, fixture_id in enumerate(FIXTURE_IDS):
        guarded = fixture_id in UNCLASSIFIED_FIXTURE_IDS and not hide_unclassified
        if guard_representative and fixture_id == "alb-health-check-complete":
            guarded = True
        rows.extend(
            (
                _run_metrics(
                    fixture_id,
                    "snapshot_only",
                    recall=0.5,
                    correct=index < 5,
                    tool_calls=2,
                    unnecessary_calls=1,
                    unsupported_statements=1,
                    guarded=guarded,
                    unclassified_correct=guarded,
                    latency_ms=10,
                    input_tokens=100,
                    output_tokens=10,
                    cost="0.1",
                ),
                _run_metrics(
                    fixture_id,
                    "hybrid_agent",
                    recall=0.75,
                    correct=index < 7,
                    tool_calls=4,
                    unnecessary_calls=1,
                    guarded=guarded,
                    unclassified_correct=(guarded and fixture_id != "composite-deploy-and-backlog"),
                    latency_ms=20,
                    input_tokens=200,
                    output_tokens=20,
                    cost="0.2",
                ),
            )
        )
    return tuple(rows)


def test_fixed_evaluation_ids_match_the_committed_manifest() -> None:
    assert (
        frozenset(fixture.fixture_id for fixture in load_manifest(MANIFEST_PATH))
        == EVALUATION_FIXTURE_IDS
    )


def test_fixed_unclassified_ids_match_manifest_variants_and_classifications() -> None:
    fixtures = load_manifest(MANIFEST_PATH)
    assert (
        frozenset(
            fixture.fixture_id
            for fixture in fixtures
            if fixture.variant in {"unknown", "composite"}
            and fixture.expected.classification == "unclassified"
        )
        == UNCLASSIFIED_FIXTURE_IDS
    )


def test_compare_modes_requires_exact_42_rows_and_aggregates_deterministically() -> None:
    comparison = compare_modes(reversed(_complete_matrix()))

    assert comparison.fixture_count == 21
    assert comparison.snapshot_only.required_evidence_recall == 0.5
    assert comparison.snapshot_only.correct_investigation_direction_count == 5
    assert comparison.snapshot_only.unnecessary_tool_ratio == 0.5
    assert comparison.snapshot_only.unsupported_claims == 21
    assert comparison.snapshot_only.unsupported_statement_claims == 21
    assert comparison.snapshot_only.unsupported_classification_claims == 0
    assert comparison.snapshot_only.unclassified_accuracy == 1.0
    assert comparison.snapshot_only.unclassified_fixture_count == 3
    assert comparison.snapshot_only.unclassified_correct_count == 3
    assert comparison.snapshot_only.tool_call_count == 42
    assert comparison.snapshot_only.unnecessary_tool_call_count == 21
    assert comparison.snapshot_only.latency_ms == 210
    assert comparison.snapshot_only.input_tokens == 2100
    assert comparison.snapshot_only.output_tokens == 210
    assert comparison.snapshot_only.estimated_cost_usd == Decimal("2.1")

    assert comparison.hybrid_agent.required_evidence_recall == 0.75
    assert comparison.hybrid_agent.correct_investigation_direction_count == 7
    assert comparison.hybrid_agent.unnecessary_tool_ratio == 0.25
    assert comparison.hybrid_agent.unclassified_accuracy == pytest.approx(2 / 3)
    assert comparison.hybrid_agent.unclassified_correct_count == 2
    assert comparison.hybrid_agent.tool_call_count == 84
    assert comparison.hybrid_agent.unnecessary_tool_call_count == 21
    assert comparison.hybrid_agent.latency_ms == 420
    assert comparison.hybrid_agent.input_tokens == 4200
    assert comparison.hybrid_agent.output_tokens == 420
    assert comparison.hybrid_agent.estimated_cost_usd == Decimal("4.2")


def test_compare_modes_rejects_hidden_unclassified_oracles() -> None:
    with pytest.raises(ValueError, match="unclassified applicability"):
        compare_modes(_complete_matrix(hide_unclassified=True))


def test_compare_modes_rejects_a_guarded_representative_fixture() -> None:
    with pytest.raises(ValueError, match="unclassified applicability"):
        compare_modes(_complete_matrix(guard_representative=True))


def test_compare_modes_rejects_an_empty_or_incomplete_matrix() -> None:
    with pytest.raises(ValueError, match="empty"):
        compare_modes(())
    with pytest.raises(ValueError, match="exact committed"):
        compare_modes(_complete_matrix()[:-1])


def test_compare_modes_rejects_duplicate_rows() -> None:
    rows = _complete_matrix()

    with pytest.raises(ValueError, match="duplicate"):
        compare_modes((*rows, rows[0]))


def test_compare_modes_rejects_extra_or_arbitrary_fixture_ids() -> None:
    extra = (
        _run_metrics("arbitrary-extra", "snapshot_only"),
        _run_metrics("arbitrary-extra", "hybrid_agent"),
    )
    arbitrary = tuple(
        _run_metrics(f"arbitrary-{index:02d}", mode) for index in range(21) for mode in MODES
    )

    with pytest.raises(ValueError, match="exact committed"):
        compare_modes((*_complete_matrix(), *extra))
    with pytest.raises(ValueError, match="exact committed"):
        compare_modes(arbitrary)


def test_compare_modes_rejects_mismatched_unclassified_oracles() -> None:
    rows = list(_complete_matrix())
    hybrid_index = next(
        index
        for index, row in enumerate(rows)
        if row.fixture_id == "unknown-sparse" and row.mode == "hybrid_agent"
    )
    rows[hybrid_index] = replace(
        rows[hybrid_index],
        unclassified_applicable=False,
        unclassified_correct=False,
    )

    with pytest.raises(ValueError, match="unclassified applicability"):
        compare_modes(rows)


@pytest.mark.parametrize("mutation", ["unsupported", "ratio", "unclassified"])
def test_compare_modes_revalidates_each_run_metric(mutation: str) -> None:
    rows = list(_complete_matrix())
    row = next(
        row for row in rows if row.fixture_id == "unknown-sparse" and row.mode == "snapshot_only"
    )
    if mutation == "unsupported":
        object.__setattr__(row, "unsupported_claims", 0)
        error = "unsupported"
    elif mutation == "ratio":
        object.__setattr__(row, "unnecessary_tool_ratio", 0.0)
        error = "Tool ratio"
    else:
        assert mutation == "unclassified"
        object.__setattr__(row, "unclassified_applicable", False)
        error = "unguarded"

    with pytest.raises(ValueError, match=error):
        compare_modes(rows)


def _mode(
    mode: EvalMode,
    *,
    fixture_count: int = 21,
    unsupported: int = 0,
    recall: float = 0.8,
    correct: int = 5,
    tool_calls: int = 0,
    unnecessary_calls: int = 0,
    unclassified_fixtures: int = 3,
    unclassified_correct: int = 2,
) -> ModeMetrics:
    return ModeMetrics(
        mode=mode,
        fixture_count=fixture_count,
        required_evidence_recall=recall,
        correct_investigation_direction_count=correct,
        unnecessary_tool_ratio=unnecessary_calls / tool_calls if tool_calls else 0.0,
        unsupported_claims=unsupported,
        unsupported_statement_claims=unsupported,
        unsupported_classification_claims=0,
        unclassified_accuracy=(
            unclassified_correct / unclassified_fixtures if unclassified_fixtures else 1.0
        ),
        unclassified_fixture_count=unclassified_fixtures,
        unclassified_correct_count=unclassified_correct,
        tool_call_count=tool_calls,
        unnecessary_tool_call_count=unnecessary_calls,
        latency_ms=0,
        input_tokens=0,
        output_tokens=0,
        estimated_cost_usd=Decimal("0"),
    )


def _safe_comparison() -> ComparisonMetrics:
    return ComparisonMetrics(
        fixture_count=21,
        snapshot_only=_mode("snapshot_only", unsupported=2, correct=5),
        hybrid_agent=_mode(
            "hybrid_agent",
            correct=7,
            tool_calls=4,
            unnecessary_calls=1,
        ),
    )


def test_gate_selects_hybrid_at_every_exact_safe_boundary() -> None:
    assert select_operating_mode(_safe_comparison()) == "hybrid_agent"


@pytest.mark.parametrize(
    "condition",
    ["unsupported", "unclassified", "recall", "unnecessary", "direction"],
)
def test_gate_falls_back_when_one_hybrid_condition_regresses(condition: str) -> None:
    comparison = _safe_comparison()
    hybrid = comparison.hybrid_agent
    if condition == "unsupported":
        hybrid = replace(hybrid, unsupported_claims=1, unsupported_statement_claims=1)
    elif condition == "unclassified":
        hybrid = replace(hybrid, unclassified_accuracy=1 / 3, unclassified_correct_count=1)
    elif condition == "recall":
        hybrid = replace(hybrid, required_evidence_recall=0.799999)
    elif condition == "unnecessary":
        hybrid = replace(
            hybrid,
            unnecessary_tool_ratio=0.5,
            unnecessary_tool_call_count=2,
        )
    else:
        assert condition == "direction"
        hybrid = replace(hybrid, correct_investigation_direction_count=6)

    assert select_operating_mode(replace(comparison, hybrid_agent=hybrid)) == "snapshot_only"


def test_mode_metrics_rejects_impossible_derived_ratios_and_counts() -> None:
    mode = _mode("hybrid_agent", tool_calls=4, unnecessary_calls=1)

    with pytest.raises(ValueError, match="Tool ratio"):
        replace(mode, unnecessary_tool_ratio=0.2)
    with pytest.raises(ValueError, match="unclassified accuracy"):
        replace(mode, unclassified_accuracy=0.5)
    with pytest.raises(ValueError, match="unclassified correct"):
        replace(mode, unclassified_correct_count=4)


def test_comparison_metrics_rejects_wrong_modes_counts_and_guarded_sets() -> None:
    comparison = _safe_comparison()
    with pytest.raises(ValueError, match="mode"):
        replace(comparison, snapshot_only=replace(comparison.snapshot_only, mode="hybrid_agent"))
    with pytest.raises(ValueError, match="exactly 21|fixture count"):
        replace(comparison, fixture_count=20)
    mismatched_guard = _mode(
        "hybrid_agent",
        correct=7,
        tool_calls=4,
        unnecessary_calls=1,
        unclassified_fixtures=2,
        unclassified_correct=1,
    )
    with pytest.raises(ValueError, match="exactly 3|guarded fixture count"):
        replace(comparison, hybrid_agent=mismatched_guard)


@pytest.mark.parametrize("guarded_count", [0, 2, 4])
def test_comparison_metrics_requires_exactly_three_guarded_fixtures(
    guarded_count: int,
) -> None:
    correct_count = min(guarded_count, 2)
    snapshot = _mode(
        "snapshot_only",
        unclassified_fixtures=guarded_count,
        unclassified_correct=correct_count,
    )
    hybrid = _mode(
        "hybrid_agent",
        correct=7,
        unclassified_fixtures=guarded_count,
        unclassified_correct=correct_count,
    )

    with pytest.raises(ValueError, match="exactly 3"):
        ComparisonMetrics(fixture_count=21, snapshot_only=snapshot, hybrid_agent=hybrid)


def test_comparison_metrics_rejects_a_consistent_two_fixture_aggregate() -> None:
    snapshot = _mode(
        "snapshot_only",
        fixture_count=2,
        correct=1,
        unclassified_fixtures=0,
        unclassified_correct=0,
    )
    hybrid = _mode(
        "hybrid_agent",
        fixture_count=2,
        correct=2,
        unclassified_fixtures=0,
        unclassified_correct=0,
    )

    with pytest.raises(ValueError, match="exactly 21"):
        ComparisonMetrics(fixture_count=2, snapshot_only=snapshot, hybrid_agent=hybrid)


def test_gate_revalidates_fixed_and_side_fixture_counts() -> None:
    small = _safe_comparison()
    object.__setattr__(small, "fixture_count", 2)
    object.__setattr__(small.snapshot_only, "fixture_count", 2)
    object.__setattr__(small.hybrid_agent, "fixture_count", 2)
    with pytest.raises(ValueError, match="exactly 21"):
        select_operating_mode(small)

    mismatched = _safe_comparison()
    object.__setattr__(mismatched.snapshot_only, "fixture_count", 20)
    with pytest.raises(ValueError, match="fixture count"):
        select_operating_mode(mismatched)


@pytest.mark.parametrize("mutation", ["unsupported", "ratio", "unclassified"])
def test_comparison_recursively_revalidates_child_mode_metrics(mutation: str) -> None:
    comparison = _safe_comparison()
    hybrid = comparison.hybrid_agent
    if mutation == "unsupported":
        object.__setattr__(hybrid, "unsupported_claims", 1)
        error = "unsupported"
    elif mutation == "ratio":
        object.__setattr__(hybrid, "unnecessary_tool_ratio", 0.0)
        error = "Tool ratio"
    else:
        assert mutation == "unclassified"
        object.__setattr__(hybrid, "unclassified_correct_count", 1)
        error = "unclassified accuracy"

    with pytest.raises(ValueError, match=error):
        comparison.__post_init__()


def test_gate_rejects_a_duck_typed_comparison() -> None:
    class DuckComparison:
        snapshot_only = _safe_comparison().snapshot_only
        hybrid_agent = _safe_comparison().hybrid_agent

    with pytest.raises(TypeError, match="exact ComparisonMetrics"):
        select_operating_mode(cast(ComparisonMetrics, DuckComparison()))
