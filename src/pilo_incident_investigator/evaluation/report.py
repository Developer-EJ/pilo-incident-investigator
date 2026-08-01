"""Deterministic, redacted reports for offline evaluation matrices."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
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
OFFLINE_EXECUTION_KIND = "offline_neutral_recording"
OFFLINE_MEASUREMENT_NOTICE = (
    "offline neutral recording은 모델을 호출하지 않았으며 0 latency/token/cost는 "
    "미측정 상태입니다. 이 결과는 실제 모델의 품질·속도·비용·안전성을 주장하지 않습니다."
)
_PROVENANCE_PATHSPECS = (
    ":(glob)src/pilo_incident_investigator/*.py",
    ":(glob)src/pilo_incident_investigator/**/*.py",
    "scripts/run_eval.py",
    ":(glob)fixtures/eval/*.yaml",
    ":(glob)fixtures/eval/**/*.yaml",
)


class LiveEvaluationUnavailable(RuntimeError):
    """Raised when a safe production live-evaluation adapter is unavailable."""


@dataclass(frozen=True, slots=True)
class GateReason:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ReportReservation:
    generated_at: datetime
    reports_dir: Path
    lock_path: Path

    def release(self) -> None:
        self.lock_path.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    git_commit: str
    git_dirty: bool
    source_fixture_digest: str


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    generated_at: datetime
    git_commit: str
    git_dirty: bool
    source_fixture_digest: str
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

    @property
    def baseline_eligible(self) -> bool:
        return not self.git_dirty


def build_offline_report(
    fixtures: Iterable[EvalFixture],
    *,
    generated_at: datetime,
    git_commit: str,
    git_dirty: bool,
    source_fixture_digest: str,
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
        git_dirty,
        source_fixture_digest,
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
        git_dirty=git_dirty,
        source_fixture_digest=source_fixture_digest,
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
    """Write a complete report pair without overwriting either final path."""
    reservation = _reserve_exact_report_slot(reports_dir, report.generated_at)
    return _write_reserved_report(report, reservation)


def reserve_report_slot(reports_dir: Path, candidate: datetime) -> ReportReservation:
    """Atomically reserve the first free timestamp at or after the candidate."""
    directory = reports_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = candidate.astimezone(UTC).replace(microsecond=0)
    while True:
        try:
            return _reserve_exact_report_slot(directory, timestamp)
        except FileExistsError:
            timestamp += timedelta(seconds=1)


def collect_source_provenance(repo_root: Path) -> SourceProvenance:
    """Return HEAD, relevant working-tree dirtiness, and a stable source/fixture digest."""
    root = repo_root.resolve()
    commit = _run_git(root, "rev-parse", "HEAD").stdout.strip()
    if not commit:
        raise RuntimeError("git commit could not be determined")
    status = _run_git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        *_PROVENANCE_PATHSPECS,
    ).stdout
    return SourceProvenance(
        git_commit=commit,
        git_dirty=bool(status),
        source_fixture_digest=_source_fixture_digest(root),
    )


def is_complete_report_pair(reports_dir: Path, generated_at: datetime) -> bool:
    """Accept only nonempty JSON/Markdown whose hashes match the completion marker."""
    json_path, markdown_path, marker_path = _final_report_paths(reports_dir.resolve(), generated_at)
    try:
        if any(
            not path.is_file() or path.stat().st_size == 0 for path in (json_path, markdown_path)
        ):
            return False
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if not isinstance(marker, dict) or set(marker) != {"json_sha256", "markdown_sha256"}:
            return False
        return marker == {
            "json_sha256": _file_digest(json_path),
            "markdown_sha256": _file_digest(markdown_path),
        }
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False


def write_reserved_report(
    report: EvaluationReport, reservation: ReportReservation
) -> tuple[Path, Path]:
    """Publish a report to a slot already reserved by this process."""
    if report.generated_at.astimezone(UTC) != reservation.generated_at:
        reservation.release()
        raise ValueError("report timestamp does not match its reserved slot")
    return _write_reserved_report(report, reservation)


def _reserve_exact_report_slot(reports_dir: Path, generated_at: datetime) -> ReportReservation:
    directory = reports_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = generated_at.astimezone(UTC).replace(microsecond=0)
    stamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
    json_path, markdown_path, marker_path = _final_report_paths(directory, timestamp)
    lock_path = directory / f".eval-{stamp}.lock"
    if json_path.exists() or markdown_path.exists() or marker_path.exists():
        raise FileExistsError(f"evaluation report already exists for timestamp {stamp}")
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise FileExistsError(f"evaluation report timestamp {stamp} is reserved") from None
    try:
        os.close(descriptor)
    except Exception:
        lock_path.unlink(missing_ok=True)
        raise
    reservation = ReportReservation(timestamp, directory, lock_path)
    if json_path.exists() or markdown_path.exists() or marker_path.exists():
        reservation.release()
        raise FileExistsError(f"evaluation report already exists for timestamp {stamp}")
    return reservation


def _write_reserved_report(
    report: EvaluationReport, reservation: ReportReservation
) -> tuple[Path, Path]:
    reports_dir = reservation.reports_dir
    stamp = report.generated_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = reports_dir / f"eval-{stamp}.json"
    markdown_path = reports_dir / f"eval-{stamp}.md"
    marker_path = reports_dir / f".eval-{stamp}.complete"
    json_temp = reports_dir / f".eval-{stamp}.json.tmp"
    markdown_temp = reports_dir / f".eval-{stamp}.md.tmp"
    marker_temp = reports_dir / f".eval-{stamp}.complete.tmp"
    created_temps: list[Path] = []
    created_outputs: list[Path] = []
    success = False
    try:
        _write_lf_text(json_temp, render_report(report, output_format="json"))
        created_temps.append(json_temp)
        _write_lf_text(markdown_temp, render_report(report, output_format="markdown"))
        created_temps.append(markdown_temp)
        _create_exclusive_file(json_path)
        created_outputs.append(json_path)
        _create_exclusive_file(markdown_path)
        created_outputs.append(markdown_path)
        _replace_file(json_temp, json_path)
        _replace_file(markdown_temp, markdown_path)
        if json_path.stat().st_size == 0 or markdown_path.stat().st_size == 0:
            raise OSError("report finals must be nonempty before completion")
        marker_content = (
            json.dumps(
                {
                    "json_sha256": _file_digest(json_path),
                    "markdown_sha256": _file_digest(markdown_path),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        _write_lf_text(marker_temp, marker_content)
        created_temps.append(marker_temp)
        _create_exclusive_file(marker_path)
        created_outputs.append(marker_path)
        _replace_file(marker_temp, marker_path)
        success = True
        return json_path, markdown_path
    finally:
        if not success:
            for path in created_outputs:
                path.unlink(missing_ok=True)
        for path in created_temps:
            path.unlink(missing_ok=True)
        reservation.release()


def aggregate_payload(report: EvaluationReport) -> dict[str, JsonValue]:
    """Return aggregate-only output suitable for stdout and CI logs."""
    payload: dict[str, JsonValue] = {
        "git_dirty": report.git_dirty,
        "source_fixture_digest": report.source_fixture_digest,
        "baseline_eligible": report.baseline_eligible,
        "execution_kind": OFFLINE_EXECUTION_KIND,
        "model_called": False,
        "measurement_notice": OFFLINE_MEASUREMENT_NOTICE,
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
        "execution_kind": OFFLINE_EXECUTION_KIND,
        "model_called": False,
        "measurement_notice": OFFLINE_MEASUREMENT_NOTICE,
        "metadata": {
            "baseline_eligible": report.baseline_eligible,
            "generated_at": _timestamp(report.generated_at),
            "git_commit": report.git_commit,
            "git_dirty": report.git_dirty,
            "model_id": report.model_id,
            "input_cost_per_million": str(report.input_cost_per_million),
            "output_cost_per_million": str(report.output_cost_per_million),
            "source_fixture_digest": report.source_fixture_digest,
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
        f"- Execution kind: {payload['execution_kind']}",
        f"- Model called: {str(payload['model_called']).lower()}",
        f"- Measurement notice: {payload['measurement_notice']}",
        f"- 생성 시각: {metadata['generated_at']}",
        f"- Git commit: {metadata['git_commit']}",
        f"- Git dirty: {str(metadata['git_dirty']).lower()}",
        f"- Source fixture digest: {metadata['source_fixture_digest']}",
        f"- Baseline eligible: {str(metadata['baseline_eligible']).lower()}",
        f"- Model ID: {metadata['model_id']}",
        f"- Input cost / 1M tokens: {metadata['input_cost_per_million']}",
        f"- Output cost / 1M tokens: {metadata['output_cost_per_million']}",
        (
            "- Baseline 상태: clean-tree 기술 조건을 충족했지만 사람의 검토가 필요합니다."
            if metadata["baseline_eligible"]
            else "- Baseline 상태: baseline 부적격 — relevant working tree가 dirty입니다."
        ),
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


def _write_lf_text(path: Path, content: str) -> None:
    created = False
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise


def _create_exclusive_file(path: Path) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.close(descriptor)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _replace_file(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _final_report_paths(reports_dir: Path, generated_at: datetime) -> tuple[Path, Path, Path]:
    stamp = generated_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return (
        reports_dir / f"eval-{stamp}.json",
        reports_dir / f"eval-{stamp}.md",
        reports_dir / f".eval-{stamp}.complete",
    )


def _file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _source_fixture_digest(root: Path) -> str:
    paths = {
        *root.joinpath("src", "pilo_incident_investigator").rglob("*.py"),
        root / "scripts" / "run_eval.py",
        *root.joinpath("fixtures", "eval").rglob("*.yaml"),
    }
    required = {
        root / "scripts" / "run_eval.py",
        root / "fixtures" / "eval" / "manifest.yaml",
    }
    if not required.issubset(paths) or any(
        not path.is_file() or path.is_symlink() for path in paths
    ):
        raise RuntimeError("evaluation provenance source set is incomplete or unsafe")
    digest = sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def _validate_metadata(
    generated_at: datetime,
    git_commit: str,
    model_id: str,
    input_rate: Decimal,
    output_rate: Decimal,
    git_dirty: bool,
    source_fixture_digest: str,
) -> None:
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    if not git_commit.strip() or not model_id.strip():
        raise ValueError("git_commit and model_id must be non-empty")
    if type(git_dirty) is not bool:
        raise TypeError("git_dirty must be an exact boolean")
    if len(source_fixture_digest) != 64 or any(
        character not in "0123456789abcdef" for character in source_fixture_digest
    ):
        raise ValueError("source_fixture_digest must be a lowercase SHA-256 hex digest")
    for name, value in (("input", input_rate), ("output", output_rate)):
        if type(value) is not Decimal or not value.is_finite() or value < 0:
            raise ValueError(f"{name} token rate must be a finite non-negative Decimal")


__all__ = [
    "METRIC_NAMES",
    "OFFLINE_MODEL_ID",
    "EvaluationReport",
    "GateReason",
    "LiveEvaluationUnavailable",
    "ReportReservation",
    "SourceProvenance",
    "aggregate_payload",
    "build_offline_report",
    "collect_source_provenance",
    "is_complete_report_pair",
    "render_report",
    "reserve_report_slot",
    "write_report",
    "write_reserved_report",
]
