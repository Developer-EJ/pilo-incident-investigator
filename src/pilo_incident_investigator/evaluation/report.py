"""Deterministic, redacted reports for offline evaluation matrices."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal, cast

from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.domain import Investigation, JsonValue, SupportedStatement
from pilo_incident_investigator.evaluation.handoff import (
    CONDITIONS,
    HandoffClaim,
    HandoffOutput,
    HandoffRecording,
    HandoffRun,
    build_handoff_prompt,
    build_offline_handoff_harness,
    fixture_digest,
    prompt_digest,
    tool_registry_identifier,
)
from pilo_incident_investigator.evaluation.metrics import (
    ComparisonMetrics,
    ModeMetrics,
    RunMetrics,
    compare_modes,
    score_run,
    select_operating_mode,
)
from pilo_incident_investigator.evaluation.runner import (
    EvaluationMeasurements,
    EvaluationMode,
    RecordedEvaluation,
    build_offline_runner,
)
from pilo_incident_investigator.evaluation.schema import EvalFixture, EvalMode
from pilo_incident_investigator.redaction import Redactor

METRIC_NAMES = (
    "required_evidence_recall",
    "correct_investigation_direction",
    "unnecessary_tool_ratio",
    "unsupported_claims",
    "unclassified_accuracy",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "estimated_cost",
    "handoff_additional_tool_calls",
    "handoff_clarification_requests",
    "handoff_safety",
)
OFFLINE_MODEL_ID = "offline-deterministic-v1"
OFFLINE_PROMPT_BUDGET = 512


class LiveEvaluationUnavailable(RuntimeError):
    """Raised when a safe production live-evaluation adapter is unavailable."""


@dataclass(frozen=True, slots=True)
class GateReason:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    generated_at: datetime
    git_commit: str
    model_id: str
    input_cost_per_million: Decimal
    output_cost_per_million: Decimal
    investigation_metrics: tuple[RunMetrics, ...]
    comparison: ComparisonMetrics
    handoff_runs: tuple[HandoffRun, ...]
    operating_mode: EvalMode
    gate_reasons: tuple[GateReason, ...]

    @property
    def metric_names(self) -> tuple[str, ...]:
        return METRIC_NAMES


def build_offline_report(
    fixtures: Iterable[EvalFixture],
    *,
    generated_at: datetime,
    git_commit: str,
    model_id: str = OFFLINE_MODEL_ID,
    input_cost_per_million: Decimal = Decimal("0"),
    output_cost_per_million: Decimal = Decimal("0"),
) -> EvaluationReport:
    """Run the exact network-free 21-by-2 investigation and handoff matrices."""
    fixture_rows = tuple(fixtures)
    _validate_metadata(
        generated_at,
        git_commit,
        model_id,
        input_cost_per_million,
        output_cost_per_million,
    )
    investigation_runs = build_offline_runner(_investigation_recordings(fixture_rows)).run_all(
        fixture_rows
    )
    fixtures_by_id = {fixture.fixture_id: fixture for fixture in fixture_rows}
    scored = tuple(
        sorted(
            (score_run(fixtures_by_id[run.fixture_id], run) for run in investigation_runs),
            key=lambda row: (row.fixture_id, row.mode),
        )
    )
    comparison = compare_modes(scored)
    handoff_runs = tuple(
        sorted(
            build_offline_handoff_harness(
                model_id=model_id,
                prompt_budget=OFFLINE_PROMPT_BUDGET,
                recordings=_handoff_recordings(fixture_rows, model_id=model_id),
            ).run_all(fixture_rows),
            key=lambda row: (row.fixture_id, row.condition),
        )
    )
    operating_mode = select_operating_mode(comparison)
    return EvaluationReport(
        generated_at=generated_at.astimezone(UTC),
        git_commit=git_commit,
        model_id=model_id,
        input_cost_per_million=input_cost_per_million,
        output_cost_per_million=output_cost_per_million,
        investigation_metrics=scored,
        comparison=comparison,
        handoff_runs=handoff_runs,
        operating_mode=operating_mode,
        gate_reasons=_gate_reasons(comparison),
    )


def render_report(
    report: EvaluationReport,
    *,
    output_format: Literal["json", "markdown"] = "json",
) -> str:
    """Render one stable report format after recursively redacting every string."""
    payload = cast(dict[str, JsonValue], _redact_strings(_report_payload(report)))
    if output_format == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output_format == "markdown":
        return _render_markdown(payload)
    raise ValueError("output_format must be json or markdown")


def write_report(report: EvaluationReport, reports_dir: Path) -> tuple[Path, Path]:
    """Write both report formats, refusing to overwrite an existing evaluation."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = reports_dir / f"eval-{stamp}.json"
    markdown_path = reports_dir / f"eval-{stamp}.md"
    if json_path.exists() or markdown_path.exists():
        raise FileExistsError(f"evaluation report already exists for timestamp {stamp}")
    json_path.write_text(
        render_report(report, output_format="json"), encoding="utf-8", newline="\n"
    )
    markdown_path.write_text(
        render_report(report, output_format="markdown"), encoding="utf-8", newline="\n"
    )
    return json_path, markdown_path


def aggregate_payload(report: EvaluationReport) -> dict[str, JsonValue]:
    """Return aggregate-only output suitable for stdout and CI logs."""
    payload: dict[str, JsonValue] = {
        "snapshot_only": _mode_payload(report.comparison.snapshot_only),
        "hybrid_agent": _mode_payload(report.comparison.hybrid_agent),
        "handoff": _handoff_aggregate(report.handoff_runs),
        "operating_mode": report.operating_mode,
        "gate_reasons": [_gate_reason_payload(reason) for reason in report.gate_reasons],
    }
    return cast(dict[str, JsonValue], _redact_strings(payload))


def _investigation_recordings(
    fixtures: tuple[EvalFixture, ...],
) -> dict[tuple[str, EvaluationMode], RecordedEvaluation]:
    recordings: dict[tuple[str, EvaluationMode], RecordedEvaluation] = {}
    zero = EvaluationMeasurements(0, 0, 0, Decimal("0"))
    for fixture in fixtures:
        summary = _snapshot_investigation(fixture)
        for mode in EvaluationMode:
            proposals: tuple[AgentProposal, ...] = ()
            if mode is EvaluationMode.HYBRID_AGENT:
                proposals = (
                    AgentProposal(
                        tool_requests=(),
                        facts=summary.facts,
                        directions=summary.directions,
                        missing=summary.missing,
                        classification=summary.classification,
                        classification_evidence_ids=summary.classification_evidence_ids,
                    ),
                )
            recordings[(fixture.fixture_id, mode)] = RecordedEvaluation(
                mode=mode,
                proposals=proposals,
                final_investigation=summary,
                measurements=zero,
            )
    return recordings


def _snapshot_investigation(fixture: EvalFixture) -> Investigation:
    facts = tuple(
        SupportedStatement(evidence.summary, (evidence.evidence_id,))
        for evidence in fixture.snapshot.evidence
    )
    missing = tuple(
        f"{failure.collector}: {failure.code} ({failure.detail})"
        for failure in fixture.snapshot.failures
    )
    if not fixture.snapshot.evidence and not missing:
        missing = ("Snapshot에 관찰 가능한 Evidence가 없습니다.",)
    return Investigation(
        facts=facts,
        directions=(),
        missing=missing,
        classification="unclassified",
        tool_calls=(),
        classification_evidence_ids=(),
    )


def _handoff_recordings(
    fixtures: tuple[EvalFixture, ...], *, model_id: str
) -> dict[tuple[str, str], HandoffRecording]:
    recordings: dict[tuple[str, str], HandoffRecording] = {}
    for fixture in fixtures:
        for condition in CONDITIONS:
            prompt = build_handoff_prompt(fixture, condition)
            claims = (
                tuple(
                    HandoffClaim(evidence.summary, (evidence.evidence_id,))
                    for evidence in fixture.snapshot.evidence
                )
                if condition == "incident_brief"
                else ()
            )
            recordings[(fixture.fixture_id, condition)] = HandoffRecording(
                fixture_id=fixture.fixture_id,
                condition=condition,
                model_id=model_id,
                prompt_budget=OFFLINE_PROMPT_BUDGET,
                prompt_digest=prompt_digest(prompt),
                fixture_digest=fixture_digest(fixture),
                tool_registry_id=tool_registry_identifier(fixture),
                output=HandoffOutput(
                    first_direction_label=None,
                    clarification_requests=(),
                    claims=claims,
                    action_proposals=(),
                    tool_requests=(),
                ),
            )
    return recordings


def _gate_reasons(comparison: ComparisonMetrics) -> tuple[GateReason, ...]:
    snapshot = comparison.snapshot_only
    hybrid = comparison.hybrid_agent
    checks = (
        (
            "hybrid_unsupported_claims_zero",
            hybrid.unsupported_claims == 0,
            f"hybrid unsupported_claims={hybrid.unsupported_claims}",
        ),
        (
            "hybrid_unsupported_claims_not_worse",
            hybrid.unsupported_claims <= snapshot.unsupported_claims,
            f"hybrid={hybrid.unsupported_claims}, snapshot={snapshot.unsupported_claims}",
        ),
        (
            "hybrid_unclassified_accuracy_not_worse",
            hybrid.unclassified_accuracy >= snapshot.unclassified_accuracy,
            f"hybrid={hybrid.unclassified_accuracy}, snapshot={snapshot.unclassified_accuracy}",
        ),
        (
            "hybrid_required_evidence_recall_not_worse",
            hybrid.required_evidence_recall >= snapshot.required_evidence_recall,
            f"hybrid={hybrid.required_evidence_recall}, "
            f"snapshot={snapshot.required_evidence_recall}",
        ),
        (
            "hybrid_unnecessary_tool_ratio_at_most_0_25",
            hybrid.unnecessary_tool_ratio <= 0.25,
            f"hybrid={hybrid.unnecessary_tool_ratio}",
        ),
        (
            "hybrid_direction_improves_by_at_least_2",
            hybrid.correct_investigation_direction_count
            >= snapshot.correct_investigation_direction_count + 2,
            "hybrid="
            f"{hybrid.correct_investigation_direction_count}, "
            f"snapshot={snapshot.correct_investigation_direction_count}",
        ),
    )
    return tuple(GateReason(name, passed, detail) for name, passed, detail in checks)


def _report_payload(report: EvaluationReport) -> dict[str, JsonValue]:
    return {
        "metadata": {
            "generated_at": _timestamp(report.generated_at),
            "git_commit": report.git_commit,
            "model_id": report.model_id,
            "input_cost_per_million": str(report.input_cost_per_million),
            "output_cost_per_million": str(report.output_cost_per_million),
        },
        "metric_names": list(report.metric_names),
        "operating_mode": report.operating_mode,
        "gate_reasons": [_gate_reason_payload(reason) for reason in report.gate_reasons],
        "aggregates": {
            "snapshot_only": _mode_payload(report.comparison.snapshot_only),
            "hybrid_agent": _mode_payload(report.comparison.hybrid_agent),
            "handoff": _handoff_aggregate(report.handoff_runs),
        },
        "investigation_runs": [_run_metric_payload(row) for row in report.investigation_metrics],
        "handoff_runs": [_handoff_run_payload(row) for row in report.handoff_runs],
    }


def _mode_payload(mode: ModeMetrics) -> dict[str, JsonValue]:
    return {
        "fixture_count": mode.fixture_count,
        "required_evidence_recall": mode.required_evidence_recall,
        "correct_investigation_direction": mode.correct_investigation_direction_count,
        "unnecessary_tool_ratio": mode.unnecessary_tool_ratio,
        "unsupported_claims": mode.unsupported_claims,
        "unclassified_accuracy": mode.unclassified_accuracy,
        "latency_ms": mode.latency_ms,
        "input_tokens": mode.input_tokens,
        "output_tokens": mode.output_tokens,
        "estimated_cost": str(mode.estimated_cost_usd),
    }


def _run_metric_payload(row: RunMetrics) -> dict[str, JsonValue]:
    return {
        "fixture_id": row.fixture_id,
        "mode": row.mode,
        "required_evidence_recall": row.required_evidence_recall,
        "correct_investigation_direction": row.correct_investigation_direction,
        "unnecessary_tool_ratio": row.unnecessary_tool_ratio,
        "unsupported_claims": row.unsupported_claims,
        "unclassified_accuracy": (
            row.unclassified_correct if row.unclassified_applicable else None
        ),
        "latency_ms": row.latency_ms,
        "input_tokens": row.input_tokens,
        "output_tokens": row.output_tokens,
        "estimated_cost": str(row.estimated_cost_usd),
    }


def _handoff_run_payload(row: HandoffRun) -> dict[str, JsonValue]:
    return {
        "fixture_id": row.fixture_id,
        "condition": row.condition,
        "model_id": row.model_id,
        "prompt_budget": row.prompt_budget,
        "handoff_additional_tool_calls": row.additional_tool_calls,
        "first_direction_label": row.first_direction_label,
        "handoff_clarification_requests": row.clarification_requests,
        "unsupported_claims": row.unsupported_claims,
        "forbidden_action_proposals": row.forbidden_action_proposals,
        "handoff_safety": (row.unsupported_claims == 0 and row.forbidden_action_proposals == 0),
    }


def _handoff_aggregate(rows: tuple[HandoffRun, ...]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for condition in CONDITIONS:
        selected = tuple(row for row in rows if row.condition == condition)
        result[condition] = {
            "run_count": len(selected),
            "handoff_additional_tool_calls": sum(row.additional_tool_calls for row in selected),
            "handoff_clarification_requests": sum(row.clarification_requests for row in selected),
            "handoff_safety": all(
                row.unsupported_claims == 0 and row.forbidden_action_proposals == 0
                for row in selected
            ),
        }
    return result


def _gate_reason_payload(reason: GateReason) -> dict[str, JsonValue]:
    return {"name": reason.name, "passed": reason.passed, "detail": reason.detail}


def _render_markdown(payload: dict[str, JsonValue]) -> str:
    metadata = cast(dict[str, JsonValue], payload["metadata"])
    aggregates = cast(dict[str, JsonValue], payload["aggregates"])
    reasons = cast(list[JsonValue], payload["gate_reasons"])
    lines = [
        "# PILO Incident Evaluation",
        "",
        f"- 생성 시각: {metadata['generated_at']}",
        f"- Git commit: {metadata['git_commit']}",
        f"- Model ID: {metadata['model_id']}",
        f"- Input cost / 1M tokens: {metadata['input_cost_per_million']}",
        f"- Output cost / 1M tokens: {metadata['output_cost_per_million']}",
        "",
        "## Metric contract",
        "",
        *(f"- `{name}`" for name in METRIC_NAMES),
        "",
        "## Aggregate metrics",
        "",
        "| mode | required evidence recall | correct direction | unnecessary Tool ratio | "
        "unsupported claims | unclassified accuracy | latency ms | input tokens | "
        "output tokens | estimated cost |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for mode in ("snapshot_only", "hybrid_agent"):
        values = cast(dict[str, JsonValue], aggregates[mode])
        lines.append(
            f"| {mode} | {values['required_evidence_recall']} | "
            f"{values['correct_investigation_direction']} | "
            f"{values['unnecessary_tool_ratio']} | {values['unsupported_claims']} | "
            f"{values['unclassified_accuracy']} | {values['latency_ms']} | "
            f"{values['input_tokens']} | {values['output_tokens']} | "
            f"{values['estimated_cost']} |"
        )
    lines.extend(
        [
            "",
            "## Gate",
            "",
            f"운영 권장 모드: {payload['operating_mode']}",
            "",
        ]
    )
    for item in reasons:
        reason = cast(dict[str, JsonValue], item)
        status = "PASS" if reason["passed"] else "FAIL"
        lines.append(f"- [{status}] {reason['name']}: {reason['detail']}")
    lines.extend(["", "## Handoff A/B", ""])
    handoff = cast(dict[str, JsonValue], aggregates["handoff"])
    for condition in CONDITIONS:
        values = cast(dict[str, JsonValue], handoff[condition])
        lines.append(
            f"- {condition}: runs={values['run_count']}, "
            f"additional_tools={values['handoff_additional_tool_calls']}, "
            f"clarifications={values['handoff_clarification_requests']}, "
            f"safe={values['handoff_safety']}"
        )
    return "\n".join(lines) + "\n"


def _redact_strings(value: JsonValue) -> JsonValue:
    redactor = Redactor()
    if isinstance(value, str):
        return redactor.redact_text(value)[0]
    if isinstance(value, list):
        return [_redact_strings(item) for item in value]
    if isinstance(value, dict):
        return {redactor.redact_text(key)[0]: _redact_strings(item) for key, item in value.items()}
    return value


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_metadata(
    generated_at: datetime,
    git_commit: str,
    model_id: str,
    input_rate: Decimal,
    output_rate: Decimal,
) -> None:
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    if not git_commit.strip() or not model_id.strip():
        raise ValueError("git_commit and model_id must be non-empty")
    for name, value in (("input", input_rate), ("output", output_rate)):
        if type(value) is not Decimal or not value.is_finite() or value < 0:
            raise ValueError(f"{name} token rate must be a finite non-negative Decimal")


__all__ = [
    "METRIC_NAMES",
    "OFFLINE_MODEL_ID",
    "EvaluationReport",
    "GateReason",
    "LiveEvaluationUnavailable",
    "aggregate_payload",
    "build_offline_report",
    "render_report",
    "write_report",
]
